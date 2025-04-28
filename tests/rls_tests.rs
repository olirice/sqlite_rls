use anyhow::Result;
use libsql::Database;
use libsql_rls::prelude::*;
use libsql_rls::parser::{Parser, RlsOperation, RlsStatement};
use libsql_rls::policy::{Policy, PolicyManager};
use pretty_assertions::assert_eq;
use tempfile::NamedTempFile;

/// Helper function to create a new in-memory database with initialization
async fn setup_test_db() -> Result<Database> {
    let db = Database::open("file::memory:?mode=memory&cache=shared")?;
    let conn = db.connect()?;

    // Create test tables
    conn.execute(
        "CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            email TEXT NOT NULL
        )",
        (),
    )
    .await?;

    conn.execute(
        "CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        (),
    )
    .await?;

    // Insert test data
    conn.execute(
        "INSERT INTO users (id, username, email) VALUES 
            (1, 'alice', 'alice@example.com'),
            (2, 'bob', 'bob@example.com'),
            (3, 'charlie', 'charlie@example.com')",
        (),
    )
    .await?;

    conn.execute(
        "INSERT INTO posts (id, user_id, title, content) VALUES 
            (1, 1, 'Alice Post 1', 'Content by Alice 1'),
            (2, 1, 'Alice Post 2', 'Content by Alice 2'),
            (3, 2, 'Bob Post 1', 'Content by Bob 1'),
            (4, 3, 'Charlie Post 1', 'Content by Charlie 1')",
        (),
    )
    .await?;

    // Set up current_user
    conn.execute(
        "CREATE TABLE _rls_current_user (user_id TEXT NOT NULL)",
        (),
    )
    .await?;

    conn.execute("INSERT INTO _rls_current_user (user_id) VALUES ('alice')", ())
        .await?;

    conn.execute(
        "CREATE FUNCTION current_user() 
         RETURNS TEXT 
         AS 'SELECT user_id FROM _rls_current_user LIMIT 1'",
        (),
    )
    .await?;

    // Initialize RLS extension
    let rls = RlsExtension::new(db.clone());
    rls.initialize().await?;

    Ok(db)
}

/// Test enabling RLS on a table
#[tokio::test]
async fn test_enable_rls() -> Result<()> {
    let db = setup_test_db().await?;
    let policy_manager = PolicyManager::new(db);

    // Enable RLS on posts table
    policy_manager.set_rls_enabled("posts", true).await?;

    // Verify RLS is enabled
    let is_enabled = policy_manager.is_rls_enabled("posts").await?;
    assert!(is_enabled);

    Ok(())
}

/// Test creating and applying a policy
#[tokio::test]
async fn test_create_and_apply_policy() -> Result<()> {
    let db = setup_test_db().await?;
    let rls = RlsExtension::new(db.clone());
    let policy_manager = PolicyManager::new(db.clone());

    // Enable RLS on posts table
    policy_manager.set_rls_enabled("posts", true).await?;

    // Create a policy that only shows posts from the current user
    let policy = Policy::new(
        "posts_user_policy",
        "posts",
        RlsOperation::Select,
        Some("user_id = (SELECT id FROM users WHERE username = current_user())".to_string()),
        None,
    );

    policy_manager.create_policy(&policy).await?;

    // Execute a SELECT query
    let conn = db.connect()?;

    // Set the current user to alice
    conn.execute("DELETE FROM _rls_current_user", ()).await?;
    conn.execute("INSERT INTO _rls_current_user (user_id) VALUES ('alice')", ())
        .await?;

    // Execute a query and check that only Alice's posts are returned
    let rows = conn
        .query_all("SELECT id, user_id, title FROM posts ORDER BY id", ())
        .await?;

    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<i64>(1)?, 1); // user_id should be 1 (Alice)
    assert_eq!(rows[1].get::<i64>(1)?, 1); // user_id should be 1 (Alice)

    // Change to Bob and verify only Bob's posts are visible
    conn.execute("DELETE FROM _rls_current_user", ()).await?;
    conn.execute("INSERT INTO _rls_current_user (user_id) VALUES ('bob')", ())
        .await?;

    let rows = conn
        .query_all("SELECT id, user_id, title FROM posts ORDER BY id", ())
        .await?;

    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<i64>(1)?, 2); // user_id should be 2 (Bob)

    Ok(())
}

/// Test the parser for RLS-specific statements
#[tokio::test]
async fn test_rls_parser() -> Result<()> {
    let parser = Parser::new();

    // Test ALTER TABLE ... ENABLE RLS
    let stmt = parser.parse_rls_statement("ALTER TABLE posts ENABLE ROW LEVEL SECURITY")?;
    match stmt {
        RlsStatement::AlterTableRls { table_name, enable } => {
            assert_eq!(table_name, "POSTS");
            assert!(enable);
        }
        _ => panic!("Expected AlterTableRls statement"),
    }

    // Test CREATE POLICY
    let stmt = parser.parse_rls_statement(
        "CREATE POLICY user_policy ON posts FOR SELECT USING (user_id = current_user_id())",
    )?;
    match stmt {
        RlsStatement::CreatePolicy {
            policy_name,
            table_name,
            operation,
            using_expr,
            check_expr,
        } => {
            assert_eq!(policy_name, "user_policy");
            assert_eq!(table_name, "posts");
            assert!(matches!(operation, RlsOperation::Select));
            assert_eq!(using_expr, Some("(user_id = current_user_id())".to_string()));
            assert_eq!(check_expr, None);
        }
        _ => panic!("Expected CreatePolicy statement"),
    }

    // Test DROP POLICY
    let stmt = parser.parse_rls_statement("DROP POLICY user_policy ON posts")?;
    match stmt {
        RlsStatement::DropPolicy {
            policy_name,
            table_name,
        } => {
            assert_eq!(policy_name, "user_policy");
            assert_eq!(table_name, "posts");
        }
        _ => panic!("Expected DropPolicy statement"),
    }

    Ok(())
}

/// Test multiple policies combined with OR
#[tokio::test]
async fn test_multiple_policies() -> Result<()> {
    let db = setup_test_db().await?;
    let policy_manager = PolicyManager::new(db.clone());

    // Enable RLS on posts table
    policy_manager.set_rls_enabled("posts", true).await?;

    // Create two policies
    let policy1 = Policy::new(
        "posts_alice_policy",
        "posts",
        RlsOperation::Select,
        Some("user_id = 1".to_string()),
        None,
    );

    let policy2 = Policy::new(
        "posts_bob_policy",
        "posts",
        RlsOperation::Select,
        Some("user_id = 2".to_string()),
        None,
    );

    policy_manager.create_policy(&policy1).await?;
    policy_manager.create_policy(&policy2).await?;

    // Execute a query - should see posts from both Alice and Bob
    let conn = db.connect()?;
    let rows = conn
        .query_all("SELECT id, user_id, title FROM posts ORDER BY id", ())
        .await?;

    assert_eq!(rows.len(), 3); // Should see 3 posts (2 from Alice, 1 from Bob)

    Ok(())
}

/// Test disabling RLS
#[tokio::test]
async fn test_disable_rls() -> Result<()> {
    let db = setup_test_db().await?;
    let policy_manager = PolicyManager::new(db.clone());

    // Enable RLS on posts table
    policy_manager.set_rls_enabled("posts", true).await?;

    // Create a policy that only shows posts from user_id 1
    let policy = Policy::new(
        "posts_user1_policy",
        "posts",
        RlsOperation::Select,
        Some("user_id = 1".to_string()),
        None,
    );

    policy_manager.create_policy(&policy).await?;

    // Execute a query - should only see posts from user_id 1
    let conn = db.connect()?;
    let rows = conn
        .query_all("SELECT id, user_id, title FROM posts ORDER BY id", ())
        .await?;

    assert_eq!(rows.len(), 2); // Should only see Alice's posts

    // Disable RLS
    policy_manager.set_rls_enabled("posts", false).await?;

    // Execute the same query - should see all posts
    let rows = conn
        .query_all("SELECT id, user_id, title FROM posts ORDER BY id", ())
        .await?;

    assert_eq!(rows.len(), 4); // Should see all posts

    Ok(())
}

/// Test the shell's parsing of RLS statements
#[tokio::test]
async fn test_shell_rls_parsing() -> Result<()> {
    let parser = Parser::new();

    // Test a variety of RLS statements
    let statements = [
        "ALTER TABLE posts ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE users DISABLE ROW LEVEL SECURITY",
        "CREATE POLICY admin_all ON posts FOR ALL USING (is_admin())",
        "CREATE POLICY user_select ON posts FOR SELECT USING (user_id = current_user_id())",
        "DROP POLICY user_select ON posts",
    ];

    for stmt in statements {
        let result = parser.parse_rls_statement(stmt);
        assert!(result.is_ok(), "Failed to parse: {}", stmt);
    }

    Ok(())
}

/// Test persistent RLS across database connections
#[tokio::test]
async fn test_persistent_rls() -> Result<()> {
    // Create a temp file for the database
    let tmp_file = NamedTempFile::new()?;
    let db_path = tmp_file.path().to_str().unwrap();
    
    // Setup the database
    {
        let db = Database::open(db_path)?;
        let rls = RlsExtension::new(db.clone());
        rls.initialize().await?;
        
        let conn = db.connect()?;
        
        // Create test tables
        conn.execute(
            "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT NOT NULL)",
            (),
        ).await?;
        
        conn.execute(
            "INSERT INTO users (id, username) VALUES (1, 'alice'), (2, 'bob')",
            (),
        ).await?;
        
        // Enable RLS
        let policy_manager = PolicyManager::new(db);
        policy_manager.set_rls_enabled("users", true).await?;
        
        // Create policy
        let policy = Policy::new(
            "users_policy",
            "users",
            RlsOperation::Select,
            Some("id = 1".to_string()),
            None,
        );
        
        policy_manager.create_policy(&policy).await?;
    }
    
    // Reopen the database and check if RLS is still active
    {
        let db = Database::open(db_path)?;
        let conn = db.connect()?;
        
        // Query should only return user with id=1
        let rows = conn.query_all("SELECT id FROM users", ()).await?;
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get::<i64>(0)?, 1);
    }
    
    Ok(())
} 