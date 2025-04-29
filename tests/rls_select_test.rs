use libsql_rls::{Result, RlsConnection};
use libsql::{Database, params};

#[tokio::test]
async fn test_rls_for_select() -> Result<()> {
    // Create a temporary in-memory database
    let db = Database::open_in_memory()?;
    let conn = db.connect()?;
    
    // Create a regular connection first to set up test data without RLS
    
    // Set up test data
    conn.execute(
        "CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT NOT NULL,
            tenant_id INTEGER NOT NULL
        )",
        params![],
    ).await?;
    
    // Insert test users with different tenant IDs
    conn.execute(
        "INSERT INTO users (id, username, tenant_id) VALUES 
        (1, 'alice', 100),
        (2, 'bob', 100),
        (3, 'charlie', 200),
        (4, 'dave', 200)",
        params![],
    ).await?;
    
    // Verify we have 4 users in the regular connection
    let mut rows = conn.query("SELECT COUNT(*) FROM users", params![]).await?;
    let row = rows.next()?.unwrap();
    let count: i64 = row.get(0)?;
    assert_eq!(count, 4, "Should have 4 users in total");
    
    // Now create the RLS connection
    let rls_conn = RlsConnection::new_initialized(conn).await?;
    
    // Create a policy: users can only see data from tenant_id = 100
    rls_conn.execute(
        "CREATE POLICY tenant_isolation ON users USING (tenant_id = 100)",
        params![],
    ).await?;
    
    // Verify the policy was stored correctly
    let mut rows = rls_conn.query(
        "SELECT name, table_name, using_expr FROM _rls_policies WHERE name = ?",
        params!["tenant_isolation"],
    ).await?;
    
    let row = rows.next()?.unwrap();
    assert_eq!(row.get::<String>(0)?, "tenant_isolation");
    assert_eq!(row.get::<String>(1)?, "users");
    
    // Apply RLS and query the users - should only get users with tenant_id = 100
    let mut rows = rls_conn.query("SELECT * FROM users", params![]).await?;
    let mut user_count = 0;
    let mut users_tenant_100 = 0;
    
    while let Some(row) = rows.next()? {
        user_count += 1;
        let tenant_id: i64 = row.get(2)?;
        if tenant_id == 100 {
            users_tenant_100 += 1;
        }
    }
    
    assert_eq!(user_count, 2, "Should only see 2 users with RLS applied");
    assert_eq!(users_tenant_100, 2, "All visible users should have tenant_id = 100");
    
    // Test with a more complex query
    let mut rows = rls_conn.query(
        "SELECT * FROM users WHERE username LIKE 'a%'", 
        params![]
    ).await?;
    
    let mut matched_users = 0;
    while let Some(row) = rows.next()? {
        matched_users += 1;
        let tenant_id: i64 = row.get(2)?;
        assert_eq!(tenant_id, 100, "RLS should be applied to complex queries");
    }
    
    assert_eq!(matched_users, 1, "Only 'alice' should match with RLS applied");
    
    Ok(())
} 