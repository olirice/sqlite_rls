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
async fn test_insert_policy() -> Result<()> {
    // Setup
    let (db_arc, conn, rls) = common::setup_test_db().await?;
    common::setup_test_tables(&conn).await?;
    
    // Create policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // Enable RLS on comments table
    common::enable_rls_default(&policy_manager, "comments").await?;
    
    // Create ownership policy for comments - users can only insert comments on their own behalf
    let check_expr = "user_id = (SELECT id FROM _rls_current_user LIMIT 1)".to_string();
    
    let policy = rls::policy::Policy::new(
        "comments_insert_check",
        "comments",
        RlsOperation::Insert,
        None,
        Some(check_expr),
    );
    
    policy_manager.create_policy(&policy).await?;
    
    // Set context to Alice (user_id = 2)
    common::set_user_context(&conn, 2, "user").await?;
    
    // Try to insert a comment as Alice (should succeed)
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "INSERT INTO comments (id, post_id, user_id, content) VALUES (5, 1, 2, 'Alice new comment')"
    ).await?;
    
    assert_eq!(res, 1); // 1 row affected
    
    // Try to insert a comment as Bob (should fail or be filtered out by RLS)
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "INSERT INTO comments (id, post_id, user_id, content) VALUES (6, 1, 3, 'Pretending to be Bob')"
    ).await?;
    
    assert_eq!(res, 0); // No rows affected - statement should be denied by RLS
    
    Ok(())
}

#[tokio::test]
async fn test_update_policy() -> Result<()> {
    // Setup
    let (db_arc, conn, rls) = common::setup_test_db().await?;
    common::setup_test_tables(&conn).await?;
    
    // Create policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // Enable RLS on comments table
    common::enable_rls_default(&policy_manager, "comments").await?;
    
    // Create ownership policy for comments - users can only update their own comments
    common::create_ownership_policy(
        &policy_manager,
        "comments_update_policy", 
        "comments", 
        &RlsOperation::Update,
        "user_id"
    ).await?;
    
    // Set context to Alice (user_id = 2)
    common::set_user_context(&conn, 2, "user").await?;
    
    // Alice tries to update her own comment
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "UPDATE comments SET content = 'Alice updated comment' WHERE id = 1"
    ).await?;
    
    assert_eq!(res, 1); // 1 row affected
    
    // Alice tries to update Bob's comment
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "UPDATE comments SET content = 'Trying to change Bob comment' WHERE id = 3"
    ).await?;
    
    assert_eq!(res, 0); // No rows affected - should be filtered out by RLS
    
    // Alice can't update comments with an UPDATE that would change ownership
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "UPDATE comments SET user_id = 3 WHERE id = 1"
    ).await?;
    
    assert_eq!(res, 0); // No rows affected - should be denied by RLS
    
    Ok(())
}

#[tokio::test]
async fn test_delete_policy() -> Result<()> {
    // Setup
    let (db_arc, conn, rls) = common::setup_test_db().await?;
    common::setup_test_tables(&conn).await?;
    
    // Create policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // Enable RLS on posts table
    common::enable_rls_default(&policy_manager, "posts").await?;
    
    // Create ownership policy for posts - users can only delete their own posts
    common::create_ownership_policy(
        &policy_manager,
        "posts_delete_policy", 
        "posts", 
        &RlsOperation::Delete,
        "user_id"
    ).await?;
    
    // Create admin bypass policy - admins can delete any post
    common::create_admin_bypass_policy(
        &policy_manager,
        "posts_admin_delete", 
        "posts", 
        &RlsOperation::Delete
    ).await?;
    
    // Set context to Alice (user_id = 2)
    common::set_user_context(&conn, 2, "user").await?;
    
    // Alice tries to delete her own post
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "DELETE FROM posts WHERE id = 1"
    ).await?;
    
    assert_eq!(res, 1); // 1 row affected
    
    // Alice tries to delete Bob's post
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "DELETE FROM posts WHERE id = 3"
    ).await?;
    
    assert_eq!(res, 0); // No rows affected - should be filtered out by RLS
    
    // Now set context to admin (user_id = 1)
    common::set_user_context(&conn, 1, "admin").await?;
    
    // Admin tries to delete Bob's post
    let res = execute_write_query_with_rls(
        &rls, 
        &conn, 
        "DELETE FROM posts WHERE id = 3"
    ).await?;
    
    assert_eq!(res, 1); // 1 row affected - admin can delete any post
    
    Ok(())
}

// Helper function to execute a write query (INSERT, UPDATE, DELETE) with RLS applied
async fn execute_write_query_with_rls(
    rls: &rls::RlsExtension,
    conn: &Connection,
    sql: &str
) -> Result<u64> {
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
    
    // Execute the rewritten query
    let result = conn.execute(&rewritten_sql, empty_params()).await?;
    
    Ok(result)
} 