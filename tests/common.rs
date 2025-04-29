use anyhow::{anyhow, Result};
use libsql::{Builder, Connection, Database, params};
use rls::compat::{ConnectionExt, empty_params};
use rls::parser::RlsOperation;
use rls::policy::PolicyManager;
use rls::RlsExt;
use rls::RlsExtension;
use std::path::Path;
use std::sync::Arc;

/// Begin a transaction for test isolation
pub async fn begin_test_transaction(conn: &Connection) -> Result<()> {
    println!("Beginning test transaction");
    conn.execute("BEGIN TRANSACTION", empty_params()).await?;
    Ok(())
}

/// Roll back a transaction after test completion
pub async fn rollback_test_transaction(conn: &Connection) -> Result<()> {
    println!("Rolling back test transaction");
    conn.execute("ROLLBACK", empty_params()).await?;
    Ok(())
}

/// Setup a test database with RLS extension and tables
pub async fn setup_test_db() -> Result<(Arc<Database>, Connection, RlsExtension)> {
    // Create a new in-memory database
    let db = Builder::new_local(":memory:")
        .build()
        .await
        .map_err(|e| anyhow!("Failed to create database: {}", e))?;

    // Create a new connection
    let conn = db
        .connect()
        .map_err(|e| anyhow!("Failed to connect: {}", e))?;

    // Create Arc for database
    let db_arc = Arc::new(db);

    // Begin a transaction for test isolation
    begin_test_transaction(&conn).await?;

    // Create test tables (users, posts, comments) BEFORE initializing RLS
    setup_test_tables(&conn).await?;

    // Initialize the RLS extension
    let rls = RlsExtension::init(&conn, "").await?;

    Ok((db_arc, conn, rls))
}

/// Setup a test database with a specific name
pub async fn setup_test_db_with_name(name: &str) -> Result<(Arc<Database>, Connection, RlsExtension)> {
    // Create a new in-memory database
    let db = Builder::new_local(":memory:")
        .build()
        .await
        .map_err(|e| anyhow!("Failed to create database: {}", e))?;

    // Create a new connection
    let conn = db
        .connect()
        .map_err(|e| anyhow!("Failed to connect: {}", e))?;
        
    // Create Arc for database
    let db_arc = Arc::new(db);

    // Begin a transaction for test isolation
    begin_test_transaction(&conn).await?;

    // Create test tables (users, posts, comments) BEFORE initializing RLS
    setup_test_tables(&conn).await?;

    // Initialize the RLS extension
    let rls = RlsExtension::init(&conn, name).await?;

    Ok((db_arc, conn, rls))
}

/// Setup test tables for RLS tests
pub async fn setup_test_tables(conn: &Connection) -> Result<()> {
    // Drop any existing tables
    conn.execute("DROP TABLE IF EXISTS comments", empty_params()).await?;
    conn.execute("DROP TABLE IF EXISTS posts", empty_params()).await?;
    conn.execute("DROP TABLE IF EXISTS users", empty_params()).await?;

    // Create tables
    create_test_tables(conn).await?;

    Ok(())
}

/// Create test tables and insert data
pub async fn create_test_tables(conn: &Connection) -> Result<()> {
    // Create users table
    conn.execute(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL
        )
        "#,
        empty_params(),
    )
    .await?;

    // Create posts table
    conn.execute(
        r#"
        CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            is_public INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
        empty_params(),
    )
    .await?;

    // Create comments table
    conn.execute(
        r#"
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            content TEXT NOT NULL,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
        "#,
        empty_params(),
    )
    .await?;

    // Insert test data

    // Users: admin, alice, bob
    conn.execute(
        r#"
        INSERT INTO users (id, name, role) VALUES
        (1, 'Admin', 'admin'),
        (2, 'Alice', 'user'),
        (3, 'Bob', 'user')
        "#,
        empty_params(),
    )
    .await?;

    // Posts: 2 for Alice, 2 for Bob
    conn.execute(
        r#"
        INSERT INTO posts (id, title, content, user_id, is_public) VALUES
        (1, 'Alice Post 1', 'Content for post 1', 2, 0),
        (2, 'Alice Post 2', 'Content for post 2', 2, 0),
        (3, 'Bob Post 1', 'Content for post 3', 3, 0),
        (4, 'Bob Post 2', 'Content for post 4', 3, 0)
        "#,
        empty_params(),
    )
    .await?;

    // Comments: 1 from Alice on Bob's post, 1 from Bob on Alice's post
    conn.execute(
        r#"
        INSERT INTO comments (id, content, post_id, user_id) VALUES
        (1, 'Nice post, Bob!', 3, 2),
        (2, 'Thanks for the comment, Alice!', 1, 3)
        "#,
        empty_params(),
    )
    .await?;

    Ok(())
}

/// Insert test data into the tables
async fn insert_test_data(conn: &Connection) -> Result<()> {
    // Begin a transaction for data insertion
    conn.execute("BEGIN TRANSACTION", empty_params()).await?;
    
    // Users: admin, alice, bob
    println!("Inserting users data...");
    conn.execute(
        "INSERT INTO users (id, name, role) VALUES 
            (1, 'admin', 'admin'),
            (2, 'alice', 'user'),
            (3, 'bob', 'user')",
        empty_params(),
    ).await?;
    
    // Posts: 2 by alice (1 public, 1 private), 2 by bob (1 public, 1 private)
    println!("Inserting posts data...");
    conn.execute(
        "INSERT INTO posts (id, user_id, title, content, is_public) VALUES 
            (1, 2, 'Alice Public Post', 'Public content by Alice', 1),
            (2, 2, 'Alice Private Post', 'Private content by Alice', 0),
            (3, 3, 'Bob Public Post', 'Public content by Bob', 1),
            (4, 3, 'Bob Private Post', 'Private content by Bob', 0)",
        empty_params(),
    ).await?;
    
    // Comments: 2 on Alice's posts, 2 on Bob's posts
    println!("Inserting comments data...");
    conn.execute(
        "INSERT INTO comments (id, post_id, user_id, content) VALUES 
            (1, 1, 2, 'Alice comment on her public post'),
            (2, 1, 3, 'Bob comment on Alice public post'),
            (3, 3, 3, 'Bob comment on his public post'),
            (4, 3, 2, 'Alice comment on Bob public post')",
        empty_params(),
    ).await?;
    
    // Commit the transaction
    conn.execute("COMMIT", empty_params()).await?;
    
    // Now verify the data was inserted
    let posts = conn.query_all("SELECT * FROM posts", empty_params()).await?;
    println!("Verification: Found {} posts after insertion", posts.len());
    if posts.len() > 0 {
        let first_post_id = posts[0].get::<i64>(0);
        println!("First post ID: {:?}", first_post_id);
    }
    
    Ok(())
}

/// Setup a user context for testing
pub async fn set_user_context(conn: &Connection, user_id: i64, role: &str) -> Result<()> {
    // Clear user context
    conn.execute("DELETE FROM _rls_current_user", empty_params())
        .await?;

    // Set new user context
    conn.execute(
        "INSERT INTO _rls_current_user (id, role) VALUES (?, ?)",
        params![user_id, role],
    )
    .await?;

    Ok(())
}

/// Get the current user ID from context
pub async fn get_current_user_id(conn: &Connection) -> Result<Option<i64>> {
    let row = conn.query_row(
        "SELECT id FROM _rls_current_user LIMIT 1",
        empty_params(),
    ).await?;
    
    match row {
        Some(row) => Ok(Some(row.get::<i64>(0)?)),
        None => Ok(None),
    }
}

/// Get the current user role from context
pub async fn get_current_user_role(conn: &Connection) -> Result<Option<String>> {
    let row = conn.query_row(
        "SELECT role FROM _rls_current_user LIMIT 1",
        empty_params(),
    ).await?;
    
    match row {
        Some(row) => Ok(Some(row.get::<String>(0)?)),
        None => Ok(None),
    }
}

/// Enable RLS for a table
pub async fn enable_rls(policy_manager: &PolicyManager, table: &str, enabled: bool) -> Result<()> {
    match policy_manager.set_rls_enabled(table, enabled).await {
        Ok(_) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Failed to set RLS: {}", e))
    }
}

/// Enable RLS for a table (with default enabled=true)
pub async fn enable_rls_default(policy_manager: &PolicyManager, table_name: &str) -> Result<()> {
    println!("Enabling RLS for table: {}", table_name);
    policy_manager.set_rls_enabled(table_name, true).await?;
    println!("RLS enabled successfully for table: {}", table_name);
    Ok(())
}

/// Create a policy that allows users to see only their own records
pub async fn create_ownership_policy(
    policy_manager: &PolicyManager,
    policy_name: &str,
    table_name: &str,
    operation: &RlsOperation,
    user_id_column: &str,
) -> Result<()> {
    println!("Creating ownership policy: {} for {}", policy_name, table_name);
    // Always use RlsOperation::Select for our simplified implementation
    let operation_copy = RlsOperation::Select;
    let using_expr = format!(
        "{} = (SELECT id FROM _rls_current_user LIMIT 1)",
        user_id_column
    );
    
    // Create a Policy object
    let policy = rls::policy::Policy::new(
        policy_name,
        table_name,
        operation_copy.clone(),
        Some(using_expr),
        None
    );
    
    policy_manager.create_policy(&policy).await?;
    
    dump_policies(policy_manager, table_name, operation).await?;
    Ok(())
}

/// Create a policy that allows viewing of public records
pub async fn create_public_visibility_policy(
    policy_manager: &PolicyManager,
    policy_name: &str,
    table: &str,
    operation: &RlsOperation,
    public_column: &str
) -> Result<()> {
    // Use a policy expression that only matches public posts
    // Note: Do NOT include the user_id condition here, as that will be handled
    // by the separate ownership policy
    let using_expr = format!("{} = 1", public_column);
    
    let policy = rls::policy::Policy::new(
        policy_name,
        table,
        operation.clone(),
        Some(using_expr),
        None,
    );
    
    // No longer check or drop existing policy
    
    // Create the policy
    println!("Creating public visibility policy: name={}, table={}, operation={:?}", 
             policy_name, table, operation);
    
    policy_manager.create_policy(&policy).await
}

/// Create a policy that bypasses RLS for admin users
pub async fn create_admin_bypass_policy(
    policy_manager: &PolicyManager,
    policy_name: &str,
    table_name: &str,
    operation: &RlsOperation,
) -> Result<()> {
    println!("Creating admin bypass policy: {} for {}", policy_name, table_name);
    // Always use RlsOperation::Select for our simplified implementation
    let operation_copy = RlsOperation::Select;
    let using_expr = r#"
        -- Admins can see everything
        (SELECT role FROM _rls_current_user LIMIT 1) = 'admin'
        OR
        -- Users can only see their own data
        user_id = (SELECT id FROM _rls_current_user LIMIT 1)
    "#.to_string();
    
    // Create a Policy object
    let policy = rls::policy::Policy::new(
        policy_name,
        table_name,
        operation_copy.clone(),
        Some(using_expr),
        None
    );
    
    policy_manager.create_policy(&policy).await?;
    
    dump_policies(policy_manager, table_name, operation).await?;
    Ok(())
}

/// Reset the test environment to a clean state
pub async fn reset_test_environment(conn: &Connection) -> Result<()> {
    // Roll back any existing transaction
    let _ = conn.execute("ROLLBACK", empty_params()).await;
    
    // Begin a new transaction
    begin_test_transaction(conn).await?;
    
    // Disable foreign keys temporarily for clean deletion
    conn.execute("PRAGMA foreign_keys = OFF", empty_params()).await?;
    
    // Check if tables exist before trying to delete from them
    println!("Checking for existing tables before clearing...");
    
    // Check if comments table exists
    let comments_exists = conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='comments'",
        empty_params()
    ).await?.is_some();
    
    // Check if posts table exists
    let posts_exists = conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='posts'",
        empty_params()
    ).await?.is_some();
    
    // Check if users table exists
    let users_exists = conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='users'",
        empty_params()
    ).await?.is_some();
    
    // Delete all data from tables in reverse dependency order (if they exist)
    println!("Clearing all data from test tables...");
    if comments_exists {
        conn.execute("DELETE FROM comments", empty_params()).await?;
    }
    
    if posts_exists {
        conn.execute("DELETE FROM posts", empty_params()).await?;
    }
    
    if users_exists {
        conn.execute("DELETE FROM users", empty_params()).await?;
    }
    
    // We no longer manage policies, so don't delete them
    
    // Re-enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON", empty_params()).await?;
    
    // Reset _rls_current_user table - this is created by RLS init if it doesn't exist
    let _ = conn.execute("DROP TABLE IF EXISTS _rls_current_user", empty_params()).await;
    
    println!("Test environment reset successfully");
    Ok(())
}

/// Dump the contents of the _rls_policies table for debugging
pub async fn dump_policies_table(conn: &Connection) -> Result<()> {
    println!("=== DUMPING _RLS_POLICIES TABLE ===");
    
    let rows = conn.query_all(
        "SELECT 
            policy_name, 
            table_name, 
            operation, 
            using_expr, 
            check_expr, 
            typeof(policy_name), 
            typeof(table_name),
            typeof(operation),
            typeof(using_expr),
            typeof(check_expr)
         FROM _rls_policies",
        empty_params(),
    ).await?;
    
    println!("Found {} rows in _rls_policies", rows.len());
    
    for (i, row) in rows.iter().enumerate() {
        println!("Row {}:", i);
        println!("  policy_name: {:?} ({})", 
            row.get::<Option<String>>(0).unwrap_or(None),
            row.get::<String>(5).unwrap_or_default()
        );
        println!("  table_name: {:?} ({})", 
            row.get::<Option<String>>(1).unwrap_or(None),
            row.get::<String>(6).unwrap_or_default()
        );
        println!("  operation: {:?} ({})", 
            row.get::<Option<String>>(2).unwrap_or(None),
            row.get::<String>(7).unwrap_or_default()
        );
        println!("  using_expr: {:?} ({})", 
            row.get::<Option<String>>(3).unwrap_or(None),
            row.get::<String>(8).unwrap_or_default()
        );
        println!("  check_expr: {:?} ({})", 
            row.get::<Option<String>>(4).unwrap_or(None),
            row.get::<String>(9).unwrap_or_default()
        );
    }
    
    println!("=== END OF DUMP ===");
    
    Ok(())
}

async fn dump_policies(
    policy_manager: &PolicyManager,
    table_name: &str,
    operation: &RlsOperation,
) -> Result<()> {
    println!("Dumping policies for table: {} and operation: {:?}", table_name, operation);
    
    // Use RlsOperation directly for get_policies
    let policies = policy_manager.get_policies(table_name, Some(operation.clone())).await?;
    
    println!("Found {} policies", policies.len());
    
    for (i, policy) in policies.iter().enumerate() {
        println!("Policy {}: {:?}", i, policy);
    }
    
    Ok(())
} 