mod common;

use anyhow::Result;
use rls::parser::RlsOperation;
use rls::policy::PolicyManager;
use rls::compat::empty_params;
use rls::compat::ConnectionExt;
use rls::RlsExt;
use libsql::Connection;
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;
use sqlparser::ast::Statement;

#[tokio::test]
async fn test_multi_table_query_with_rls() -> Result<()> {
    // Setup
    let (db_arc, conn, rls) = common::setup_test_db().await?;
    common::setup_test_tables(&conn).await?;
    
    // Create policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // Enable RLS on posts table
    common::enable_rls_default(&policy_manager, "posts").await?;
    
    // Create ownership policy for posts - users can only see their own posts
    common::create_ownership_policy(
        &policy_manager,
        "posts_ownership", 
        "posts", 
        &RlsOperation::Select,
        "user_id"
    ).await?;
    
    // Create a policy allowing viewing of public posts
    common::create_public_visibility_policy(
        &policy_manager,
        "posts_public_visibility", 
        "posts", 
        &RlsOperation::Select,
        "is_public"
    ).await?;
    
    // Enable RLS on comments table
    common::enable_rls_default(&policy_manager, "comments").await?;
    
    // Create ownership policy for comments - users can only see their own comments
    common::create_ownership_policy(
        &policy_manager,
        "comments_ownership", 
        "comments", 
        &RlsOperation::Select,
        "user_id"
    ).await?;
    
    // Set context to Alice (user_id = 2)
    common::set_user_context(&conn, 2, "user").await?;
    
    // Query for posts with their comments, including join
    let results = execute_select_with_rls(
        &rls, 
        &conn, 
        "SELECT p.id, p.title, c.content 
         FROM posts p 
         LEFT JOIN comments c ON p.id = c.post_id 
         ORDER BY p.id, c.id"
    ).await?;
    
    // Alice should see:
    // - Her 2 posts (id 1, 2)
    // - Bob's 1 public post (id 3)
    // - Her own comments (id 1, 4)
    // But not:
    // - Bob's private post (id 4)
    // - Bob's comments (id 2, 3)
    
    // We should see at least 3 rows (Alice's 2 posts and Bob's public post)
    // Additional rows for comments that Alice can see
    assert!(results.len() >= 3);
    
    // The first post should be Alice's public post (id 1)
    let post_id: i64 = results[0].get(0)?;
    assert_eq!(post_id, 1);
    
    Ok(())
}

/// This test verifies that policies are evaluated with OR semantics
#[tokio::test]
async fn test_policy_hierarchy_and_precedence() -> Result<()> {
    // Setup
    let (db_arc, conn, rls) = common::setup_test_db().await?;
    common::setup_test_tables(&conn).await?;
    
    // Create policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // Enable RLS on posts table
    common::enable_rls_default(&policy_manager, "posts").await?;
    
    // Create a restrictive policy first - deny all except specific title
    let restrictive_policy = rls::policy::Policy::new(
        "posts_restrictive",
        "posts",
        RlsOperation::Select,
        Some("title = 'Alice Public Post'".to_string()),
        None,
    );
    
    policy_manager.create_policy(&restrictive_policy).await?;
    
    // Create ownership policy for posts - users can see their own posts
    common::create_ownership_policy(
        &policy_manager,
        "posts_ownership", 
        "posts", 
        &RlsOperation::Select,
        "user_id"
    ).await?;
    
    // Set context to Alice (user_id = 2)
    common::set_user_context(&conn, 2, "user").await?;
    
    // Query posts with RLS - the policies should be combined with OR semantics
    let results = execute_select_with_rls(&rls, &conn, "SELECT * FROM posts ORDER BY id").await?;
    
    // Alice should see both her posts (id 1, 2) because of OR semantics
    assert_eq!(results.len(), 2, "Alice should see 2 posts, found {}", results.len());
    
    // Now create a restrictive check policy for UPDATE
    let check_policy = rls::policy::Policy::new(
        "posts_update_check",
        "posts",
        RlsOperation::Update,
        Some("user_id = (SELECT id FROM _rls_current_user LIMIT 1)".to_string()),
        Some("title NOT LIKE '%forbidden%'".to_string()),
    );
    
    policy_manager.create_policy(&check_policy).await?;
    
    // Alice tries to update her post with acceptable title
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "UPDATE posts SET title = 'Alice Updated Post' WHERE id = 1"
    ).await?;
    
    assert!(res > 0, "Update should affect at least one row"); // 1 row affected
    
    // Alice tries to update her post with forbidden title
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "UPDATE posts SET title = 'Alice forbidden update' WHERE id = 1"
    ).await?;
    
    assert_eq!(res, 0, "Update with forbidden title should be blocked"); // No rows affected - should be denied by RLS
    
    Ok(())
}

#[tokio::test]
async fn test_policy_enabling_and_disabling() -> Result<()> {
    // Setup
    let (db_arc, conn, rls) = common::setup_test_db().await?;
    common::setup_test_tables(&conn).await?;
    
    // Create policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // First query posts without RLS
    let sql = "SELECT * FROM posts";
    let results = conn.query_all(sql, empty_params()).await?;
    
    // Should see all 4 posts without RLS
    assert_eq!(results.len(), 4);
    
    // Enable RLS on posts table
    common::enable_rls_default(&policy_manager, "posts").await?;
    
    // Create ownership policy for posts
    common::create_ownership_policy(
        &policy_manager,
        "posts_ownership", 
        "posts", 
        &RlsOperation::Select,
        "user_id"
    ).await?;
    
    // Set context to Alice (user_id = 2)
    common::set_user_context(&conn, 2, "user").await?;
    
    // Query posts with RLS
    let results = execute_select_with_rls(&rls, &conn, "SELECT * FROM posts").await?;
    
    // Alice should see only her 2 posts with RLS enabled
    assert_eq!(results.len(), 2);
    
    // Disable RLS on posts table
    common::enable_rls(&policy_manager, "posts", false).await?;
    
    // Query posts again after disabling RLS
    let results = conn.query_all(sql, empty_params()).await?;
    
    // Should see all 4 posts again
    assert_eq!(results.len(), 4);
    
    Ok(())
}

// Helper functions to execute queries with RLS

async fn execute_select_with_rls(
    rls: &rls::RlsExtension,
    conn: &Connection,
    sql: &str
) -> Result<Vec<libsql::Row>> {
    // Parse the SQL
    let dialect = SQLiteDialect {};
    let statements = Parser::parse_sql(&dialect, sql)?;
    
    if statements.is_empty() {
        return Ok(Vec::new());
    }
    
    // Get the first statement and rewrite with RLS
    let rewriter = rls.rewriter();
    let rewritten_stmt = rewriter.rewrite(statements[0].clone()).await?;
    
    // Convert back to SQL string
    let rewritten_sql = rewritten_stmt.to_string();
    
    // Using prepare/query approach to handle NULL values better
    let mut stmt = conn.prepare(&rewritten_sql).await?;
    let mut rows = stmt.query([] as [libsql::Value; 0]).await?;
    let mut result = Vec::new();
    
    while let Some(row) = rows.next().await? {
        result.push(row);
    }
    
    Ok(result)
}

async fn execute_write_query_with_rls(
    rls: &rls::RlsExtension,
    conn: &Connection,
    sql: &str
) -> Result<usize> {
    // Parse the SQL
    let dialect = SQLiteDialect {};
    let statements = Parser::parse_sql(&dialect, sql)?;
    
    if statements.is_empty() {
        return Ok(0);
    }
    
    // Get the first statement and rewrite with RLS
    let rewriter = rls.rewriter();
    let rewritten_stmt = rewriter.rewrite(statements[0].clone()).await?;
    
    // Convert back to SQL string
    let rewritten_sql = rewritten_stmt.to_string();
    
    // Using prepared statement approach as with the SELECT query
    let mut stmt = conn.prepare(&rewritten_sql).await?;
    let result = stmt.execute([] as [libsql::Value; 0]).await?;
    
    Ok(result)
} 