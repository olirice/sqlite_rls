use anyhow::Result;
use libsql::{Connection, Rows, Builder};
use rls::compat::empty_params;
use sqlparser::ast::{self, Expr, Statement};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

#[tokio::main]
async fn main() -> Result<()> {
    // Open an in-memory database using the Builder pattern
    let db = Builder::new_local("file::memory:?mode=memory&cache=shared").build().await?;
    println!("Database opened successfully");
    
    // Create a connection
    let conn = db.connect()?;
    println!("Connected to database");
    
    // Create test tables and data for RLS demo
    setup_database(&conn).await?;
    
    // Query without RLS
    println!("\nQuery without RLS:");
    let rows = query_posts(&conn, "SELECT * FROM posts").await?;
    print_posts(rows).await?;
    
    // Query with RLS for user 1 (Alice)
    println!("\nQuery with RLS for user_id = 1 (Alice):");
    let rows = query_with_rls(&conn, "SELECT * FROM posts", 1).await?;
    print_posts(rows).await?;
    
    // Query with RLS for user 2 (Bob)
    println!("\nQuery with RLS for user_id = 2 (Bob):");
    let rows = query_with_rls(&conn, "SELECT * FROM posts", 2).await?;
    print_posts(rows).await?;
    
    println!("\nDemo completed successfully!");
    Ok(())
}

// Set up the example database with tables and test data
async fn setup_database(conn: &Connection) -> Result<()> {
    // Create test tables
    conn.execute(
        "CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT NOT NULL)",
        empty_params(),
    ).await?;
    
    conn.execute(
        "CREATE TABLE posts (
            id INTEGER PRIMARY KEY, 
            user_id INTEGER NOT NULL, 
            title TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )",
        empty_params(),
    ).await?;
    
    // Insert test data
    conn.execute(
        "INSERT INTO users (id, name) VALUES (1, 'Alice'), (2, 'Bob')",
        empty_params(),
    ).await?;
    
    conn.execute(
        "INSERT INTO posts (id, user_id, title) VALUES 
            (1, 1, 'Alice Post 1'),
            (2, 1, 'Alice Post 2'),
            (3, 2, 'Bob Post 1'),
            (4, 2, 'Bob Post 2')",
        empty_params(),
    ).await?;
    
    println!("Created database schema and inserted test data");
    Ok(())
}

// Execute a query with RLS applied
async fn query_with_rls(conn: &Connection, sql: &str, user_id: i64) -> Result<Rows> {
    // Parse the SQL to get AST
    let dialect = SQLiteDialect {};
    
    // Parse the SQL using the static method of Parser that takes dialect as argument
    let stmts = Parser::parse_sql(&dialect, sql)?;
    
    if stmts.is_empty() {
        return Err(anyhow::anyhow!("Empty SQL statement"));
    }
    
    // Apply RLS policy to the AST
    let mut stmt = stmts[0].clone();
    apply_rls(&mut stmt, user_id)?;
    
    // Execute the transformed query
    let transformed_sql = stmt.to_string();
    println!("Transformed SQL: {}", transformed_sql);
    
    let rows = conn.query(&transformed_sql, empty_params()).await?;
    Ok(rows)
}

// Execute a simple query
async fn query_posts(conn: &Connection, sql: &str) -> Result<Rows> {
    let rows = conn.query(sql, empty_params()).await?;
    Ok(rows)
}

// Print posts from query results
async fn print_posts(mut rows: Rows) -> Result<()> {
    println!("| ID | User ID | Title      |");
    println!("|----+---------|------------|");
    
    while let Some(row) = rows.next().await? {
        println!("| {} | {} | {} |", 
                row.get::<i64>(0)?, 
                row.get::<i64>(1)?, 
                row.get::<String>(2)?);
    }
    
    Ok(())
}

// Apply a simple RLS policy to a SQL statement
fn apply_rls(stmt: &mut Statement, user_id: i64) -> Result<()> {
    if let Statement::Query(query) = stmt {
        if let ast::SetExpr::Select(select) = &mut *query.body {
            // Create a simple condition to filter by user_id
            let condition = Expr::BinaryOp {
                left: Box::new(Expr::Identifier(ast::Ident::new("user_id"))),
                op: ast::BinaryOperator::Eq,
                right: Box::new(Expr::Value(ast::Value::Number(user_id.to_string(), false))),
            };
            
            // If there's already a WHERE clause, AND it with our condition
            if let Some(existing_where) = &select.selection {
                select.selection = Some(Expr::BinaryOp {
                    left: Box::new(existing_where.clone()),
                    op: ast::BinaryOperator::And,
                    right: Box::new(condition),
                });
            } else {
                // Otherwise just set our condition
                select.selection = Some(condition);
            }
        }
    }
    
    Ok(())
} 