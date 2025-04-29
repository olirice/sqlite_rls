use anyhow::Result;
use libsql::{Builder, Connection, Database, Value};
use rls::compat::empty_params;
use rls::compat::ConnectionExt;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<()> {
    // Create an in-memory database for testing
    println!("Creating in-memory database...");
    let db = Builder::new_local("file:memdb_debug?mode=memory&cache=shared")
        .build()
        .await?;
    
    // Create a connection
    println!("Creating database connection...");
    let conn = db.connect()?;
    
    // Create test tables
    println!("Creating test tables...");
    
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
    
    // Create posts table
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
    
    // Insert test data
    println!("Inserting users data...");
    conn.execute(
        "INSERT INTO users (id, name, role) VALUES 
            (1, 'admin', 'admin'),
            (2, 'alice', 'user'),
            (3, 'bob', 'user')",
        empty_params(),
    ).await?;
    
    println!("Inserting posts data...");
    conn.execute(
        "INSERT INTO posts (id, user_id, title, content, is_public) VALUES 
            (1, 2, 'Alice Public Post', 'Public content by Alice', 1),
            (2, 2, 'Alice Private Post', 'Private content by Alice', 0),
            (3, 3, 'Bob Public Post', 'Public content by Bob', 1),
            (4, 3, 'Bob Private Post', 'Private content by Bob', 0)",
        empty_params(),
    ).await?;
    
    // Verify data exists in posts table
    println!("\nVerifying data in posts table with direct query:");
    let direct_rows = conn.query_all("SELECT * FROM posts", empty_params()).await?;
    println!("Direct query found {} posts", direct_rows.len());
    
    // Debug: Print table schema
    println!("\nTable schema:");
    if !direct_rows.is_empty() {
        for i in 0..direct_rows[0].column_count() {
            println!("Column {}: Name={}", i, direct_rows[0].column_name(i).unwrap_or("<unknown>"));
        }
    }
    
    // Debug: Test different ways of accessing the data to see which works
    println!("\nAccessing data with different methods:");
    for (i, row) in direct_rows.iter().enumerate() {
        println!("\nPost {}:", i);
        
        // Method 1: Using get with type
        println!("Method 1 (get<i64>):");
        println!("  id = {:?}", row.get::<i64>(0));
        println!("  user_id = {:?}", row.get::<i64>(1));
        println!("  title = {:?}", row.get::<String>(2));
        
        // Method 2: Using get_value for raw Value
        println!("Method 2 (get::<Value>):");
        println!("  id = {:?}", row.get::<Value>(0));
        println!("  user_id = {:?}", row.get::<Value>(1));
        println!("  title = {:?}", row.get::<Value>(2));
    }
    
    // Try with explicit parameters query
    println!("\nTrying with explicit parameter query:");
    let param_rows = conn.query_all("SELECT * FROM posts WHERE user_id = ?", [2i64]).await?;
    println!("Parameter query found {} posts for user_id = 2", param_rows.len());
    
    if !param_rows.is_empty() {
        let row = &param_rows[0];
        println!("First row:");
        println!("  id = {:?}", row.get::<i64>(0));
        println!("  user_id = {:?}", row.get::<i64>(1));
        println!("  title = {:?}", row.get::<String>(2));
    }
    
    Ok(())
} 