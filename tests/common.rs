use anyhow::Result;
use libsql::{Builder, Connection, Database};
use rls::prelude::*;
use rls::compat::empty_params;
use rls::RlsExtension;
use rls::parser::RlsOperation;
use rls::policy::{Policy, PolicyManager};
use rls::RlsExt;
use std::sync::Arc;

/// Setup a test database with RLS extension and tables
pub async fn setup_test_db() -> Result<(Arc<Database>, Connection, RlsExtension)> {
    setup_test_db_with_name("test_db").await
}

/// Setup a test database with RLS extension and tables, using a specific database name
pub async fn setup_test_db_with_name(db_name: &str) -> Result<(Arc<Database>, Connection, RlsExtension)> {
    // Use a temporary directory for test databases
    let temp_dir = std::env::temp_dir();
    let unique_id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros();
    
    let db_path = temp_dir.join(format!("{}_{}.db", db_name, unique_id));
    let db_path_str = db_path.to_str().unwrap();
    
    // Create a file-based database for testing
    println!("Creating database at path: {}", db_path_str);
    let db = Builder::new_local(db_path_str)
        .build()
        .await?;
    
    // Create a connection
    println!("Creating database connection...");
    let conn = db.connect()?;
    
    // Initialize RLS extension
    println!("Setting up RLS extension...");
    let db_arc = Arc::new(db);
    let mut rls = RlsExtension::new(db_arc.clone());
    
    // Step 1: Attempt to initialize RLS
    println!("Initializing RLS extension...");
    rls.initialize().await?;
    println!("RLS initialization complete.");
    
    // Step 2: Check if _rls_tables exists using SQLITE_MASTER with the same connection
    println!("Checking for _rls_tables in sqlite_master...");
    let row = conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_tables'",
        empty_params(),
    ).await?;
    
    match &row {
        Some(_) => println!("_rls_tables found in sqlite_master."),
        None => println!("_rls_tables NOT found in sqlite_master!"),
    }
    
    if row.is_none() {
        // Try creating the tables directly as a fallback
        println!("Tables not found, creating directly...");
        
        // Begin a transaction to ensure atomic operations
        conn.execute("BEGIN TRANSACTION", empty_params()).await?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _rls_tables (
                table_name TEXT PRIMARY KEY,
                enabled BOOLEAN NOT NULL DEFAULT 0
            )",
            empty_params(),
        ).await?;
        
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _rls_policies (
                policy_name TEXT NOT NULL,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                using_expr TEXT,
                check_expr TEXT,
                PRIMARY KEY (policy_name, table_name),
                FOREIGN KEY (table_name) REFERENCES _rls_tables(table_name)
            )",
            empty_params(),
        ).await?;
        
        // Commit the transaction
        conn.execute("COMMIT", empty_params()).await?;
        
        println!("Tables created directly.");
    }
    
    // Step 3: Try to query the _rls_tables directly
    println!("Attempting to query _rls_tables directly...");
    let tables_result = conn.query_all(
        "SELECT table_name FROM _rls_tables",
        empty_params(),
    ).await;
    
    match tables_result {
        Ok(rows) => println!("Successfully queried _rls_tables. Found {} rows.", rows.len()),
        Err(e) => println!("Error querying _rls_tables: {}", e),
    }
    
    // Setup test tables
    println!("Setting up test tables...");
    setup_test_tables(&conn).await?;
    println!("Test tables setup complete.");
    
    Ok((db_arc, conn, rls))
}

/// Setup test tables for RLS tests
pub async fn setup_test_tables(conn: &Connection) -> Result<()> {
    println!("Setting up test tables...");
    create_test_tables(conn).await?;
    println!("Test tables setup complete.");
    Ok(())
}

/// Create test tables and insert data
pub async fn create_test_tables(conn: &Connection) -> Result<()> {
    // Enable foreign key constraints
    conn.execute("PRAGMA foreign_keys = OFF", empty_params()).await?;
    
    // Begin a transaction to ensure atomic operations
    conn.execute("BEGIN TRANSACTION", empty_params()).await?;
    
    // First drop existing tables if they exist to avoid constraint violations
    println!("Dropping existing tables if they exist...");
    conn.execute("DROP TABLE IF EXISTS comments", empty_params()).await?;
    conn.execute("DROP TABLE IF EXISTS posts", empty_params()).await?;
    conn.execute("DROP TABLE IF EXISTS users", empty_params()).await?;
    
    // Create users table
    println!("Creating users table...");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            role TEXT NOT NULL
        )",
        empty_params(),
    ).await?;
    
    // Create posts table (with user_id for ownership)
    println!("Creating posts table...");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            is_public BOOLEAN NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        empty_params(),
    ).await?;
    
    // Create comments table (with user_id for ownership)
    println!("Creating comments table...");
    conn.execute(
        "CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY,
            post_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            FOREIGN KEY (post_id) REFERENCES posts(id),
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        empty_params(),
    ).await?;
    
    // Insert test data in the same transaction
    println!("Inserting test data...");
    
    // Users: admin, alice, bob
    conn.execute(
        "INSERT INTO users (id, name, role) VALUES 
            (1, 'admin', 'admin'),
            (2, 'alice', 'user'),
            (3, 'bob', 'user')",
        empty_params(),
    ).await?;
    
    // Posts: 2 by alice (1 public, 1 private), 2 by bob (1 public, 1 private)
    conn.execute(
        "INSERT INTO posts (id, user_id, title, content, is_public) VALUES 
            (1, 2, 'Alice Public Post', 'Public content by Alice', 1),
            (2, 2, 'Alice Private Post', 'Private content by Alice', 0),
            (3, 3, 'Bob Public Post', 'Public content by Bob', 1),
            (4, 3, 'Bob Private Post', 'Private content by Bob', 0)",
        empty_params(),
    ).await?;
    
    // Comments: 2 on Alice's posts, 2 on Bob's posts
    conn.execute(
        "INSERT INTO comments (id, post_id, user_id, content) VALUES 
            (1, 1, 3, 'Comment by Bob on Alice public post'),
            (2, 2, 3, 'Comment by Bob on Alice private post'),
            (3, 3, 2, 'Comment by Alice on Bob public post'),
            (4, 4, 2, 'Comment by Alice on Bob private post')",
        empty_params(),
    ).await?;
    
    // Commit the transaction
    conn.execute("COMMIT", empty_params()).await?;
    
    // Re-enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON", empty_params()).await?;
    
    // Verify data was inserted correctly
    println!("Verification: Found {} posts after insertion", 
             conn.query_all("SELECT * FROM posts", empty_params()).await?.len());
    
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
    // Begin a transaction
    conn.execute("BEGIN TRANSACTION", empty_params()).await?;
    
    // Check if the user context table exists
    let table_exists = conn.query_row(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_current_user'",
        empty_params(),
    ).await?;
    
    if table_exists.is_none() {
        // Create the user context table if it doesn't exist
        conn.execute(
            "CREATE TABLE _rls_current_user (
                id INTEGER NOT NULL,
                role TEXT NOT NULL
            )",
            empty_params(),
        ).await?;
    } else {
        // Clear existing entries
        conn.execute(
            "DELETE FROM _rls_current_user",
            empty_params(),
        ).await?;
    }
    
    // Insert the new user context
    conn.execute(
        "INSERT INTO _rls_current_user (id, role) VALUES (?, ?)",
        (user_id, role),
    ).await?;
    
    // Commit the transaction
    conn.execute("COMMIT", empty_params()).await?;
    
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
    policy_manager.set_rls_enabled(table, enabled).await
}

/// Enable RLS for a table (with default enabled=true)
pub async fn enable_rls_default(policy_manager: &PolicyManager, table: &str) -> Result<()> {
    policy_manager.set_rls_enabled(table, true).await
}

/// Create a policy that allows users to see only their own records
pub async fn create_ownership_policy(
    policy_manager: &PolicyManager,
    policy_name: &str,
    table: &str,
    operation: &RlsOperation,
    user_id_column: &str
) -> Result<()> {
    let using_expr = format!("{} = (SELECT id FROM _rls_current_user LIMIT 1)", user_id_column);
    
    let policy = Policy::new(
        policy_name,
        table,
        operation.clone(),
        Some(using_expr),
        None,
    );
    
    // First ensure the policy doesn't already exist
    if let Ok(true) = policy_manager.policy_exists(policy_name, table).await {
        // Delete existing policy
        println!("Policy already exists, dropping it first");
        let _ = policy_manager.drop_policy(policy_name, table).await;
    }
    
    // Create the policy
    println!("Creating ownership policy: name={}, table={}, operation={:?}", 
             policy_name, table, operation);
    let result = policy_manager.create_policy(&policy).await;
    
    // Verify the policy was created
    if let Ok(Some(created_policy)) = policy_manager.get_policy(policy_name, table).await {
        println!("Verified policy was created: name={}, operation={:?}, using_expr={:?}",
                 created_policy.name(), created_policy.operation(), created_policy.using_expr());
    } else {
        println!("WARNING: Could not verify policy creation!");
    }
    
    result
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
    
    let policy = Policy::new(
        policy_name,
        table,
        operation.clone(),
        Some(using_expr),
        None,
    );
    
    // First ensure the policy doesn't already exist
    if let Ok(true) = policy_manager.policy_exists(policy_name, table).await {
        // Delete existing policy
        println!("Policy already exists, dropping it first");
        let _ = policy_manager.drop_policy(policy_name, table).await;
    }
    
    // Create the policy
    println!("Creating public visibility policy: name={}, table={}, operation={:?}", 
             policy_name, table, operation);
    
    policy_manager.create_policy(&policy).await
}

/// Create a policy that bypasses RLS for admin users
pub async fn create_admin_bypass_policy(
    policy_manager: &PolicyManager,
    policy_name: &str,
    table: &str,
    operation: &RlsOperation,
) -> Result<()> {
    // Admin users (role='admin') can see all records
    // This expression should evaluate to TRUE when the current user has role='admin'
    let using_expr = "(SELECT role FROM _rls_current_user LIMIT 1) = 'admin'";
    
    let policy = Policy::new(
        policy_name,
        table,
        operation.clone(),
        Some(using_expr.to_string()),
        None,
    );
    
    // First ensure the policy doesn't already exist
    if let Ok(true) = policy_manager.policy_exists(policy_name, table).await {
        // Delete existing policy
        println!("Policy already exists, dropping it first");
        let _ = policy_manager.drop_policy(policy_name, table).await;
    }
    
    // Create the policy
    println!("Creating admin bypass policy: name={}, table={}, operation={:?}", 
             policy_name, table, operation);
    
    policy_manager.create_policy(&policy).await
}

/// Reset the test environment to a clean state
pub async fn reset_test_environment(conn: &Connection) -> Result<()> {
    // Disable foreign keys temporarily for clean deletion
    conn.execute("PRAGMA foreign_keys = OFF", empty_params()).await?;
    
    // Delete all data from tables in reverse dependency order
    println!("Clearing all data from test tables...");
    conn.execute("DELETE FROM comments", empty_params()).await?;
    conn.execute("DELETE FROM posts", empty_params()).await?;
    conn.execute("DELETE FROM users", empty_params()).await?;
    conn.execute("DELETE FROM _rls_policies", empty_params()).await?;
    conn.execute("DELETE FROM _rls_tables", empty_params()).await?;
    
    // Re-enable foreign keys
    conn.execute("PRAGMA foreign_keys = ON", empty_params()).await?;
    
    // Reset _rls_current_user table
    conn.execute("DROP TABLE IF EXISTS _rls_current_user", empty_params()).await?;
    
    println!("Test environment reset successfully");
    Ok(())
} 