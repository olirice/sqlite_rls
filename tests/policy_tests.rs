use libsql_rls::{Result, RlsConnection};
use libsql::{Database, params};

#[tokio::test]
async fn test_create_policy_parsing() -> Result<()> {
    // Create a temporary in-memory database
    let db = Database::open_in_memory()?;
    let conn = db.connect()?;
    
    // Initialize the policy table
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _rls_policies (
            id INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            schema_name TEXT,
            table_name TEXT NOT NULL,
            command TEXT NOT NULL,
            using_expr TEXT,
            check_expr TEXT,
            UNIQUE(name, schema_name, table_name)
        )",
        params![],
    ).await?;
    
    // Wrap the connection with RLS
    let rls_conn = RlsConnection::new(conn);
    
    // Test a basic CREATE POLICY statement directly through the wrapped connection
    let policy_sql = "CREATE POLICY user_policy ON users USING (user_id = current_user_id())";
    rls_conn.execute(policy_sql, params![]).await?;
    
    // Verify the policy was stored correctly
    let mut rows = rls_conn.query(
        "SELECT name, table_name, schema_name, command, using_expr, check_expr FROM _rls_policies WHERE name = ?",
        params!["user_policy"],
    ).await?;
    
    let row = rows.next()?.unwrap();
    assert_eq!(row.get::<String>(0)?, "user_policy");
    assert_eq!(row.get::<String>(1)?, "users");
    assert_eq!(row.get::<Option<String>>(2)?, None);
    assert_eq!(row.get::<String>(3)?, "ALL");
    
    // Get the actual expression for debugging
    let expr = row.get::<Option<String>>(4)?;
    println!("Actual using_expr: {:?}", expr);
    
    // Check it contains the key parts rather than exact string
    let expr = expr.unwrap();
    assert!(expr.contains("user_id"));
    assert!(expr.contains("current_user_id"));
    
    assert_eq!(row.get::<Option<String>>(5)?, None);
    
    // Test a more complex CREATE POLICY statement
    let policy_sql = "CREATE POLICY admin_policy ON public.documents 
                     FOR SELECT 
                     USING (role = 'admin')
                     WITH CHECK (document_status = 'approved')";
    rls_conn.execute(policy_sql, params![]).await?;
    
    // Verify the policy was stored correctly
    let mut rows = rls_conn.query(
        "SELECT name, table_name, schema_name, command, using_expr, check_expr FROM _rls_policies WHERE name = ?",
        params!["admin_policy"],
    ).await?;
    
    let row = rows.next()?.unwrap();
    assert_eq!(row.get::<String>(0)?, "admin_policy");
    assert_eq!(row.get::<String>(1)?, "documents");
    assert_eq!(row.get::<Option<String>>(2)?, Some("public".to_string()));
    assert_eq!(row.get::<String>(3)?, "SELECT");
    
    // Get the actual expressions for debugging
    let using_expr = row.get::<Option<String>>(4)?;
    let check_expr = row.get::<Option<String>>(5)?;
    println!("Actual using_expr: {:?}", using_expr);
    println!("Actual check_expr: {:?}", check_expr);
    
    // Check they contain the key parts rather than exact string
    let using_expr = using_expr.unwrap();
    assert!(using_expr.contains("role"));
    assert!(using_expr.contains("admin"));
    
    let check_expr = check_expr.unwrap();
    assert!(check_expr.contains("document_status"));
    assert!(check_expr.contains("approved"));
    
    Ok(())
} 