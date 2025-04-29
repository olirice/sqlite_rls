use libsql_rls::{Result, RlsConnection};
use libsql::{Database, params};
use std::env;
use std::path::Path;
use std::io::{self, Write};

// Interactive RLS REPL to demonstrate Row Level Security in action
#[tokio::main]
async fn main() -> Result<()> {
    // Check for command line arguments
    let args: Vec<String> = env::args().collect();
    let db_path = if args.len() > 1 { &args[1] } else { "demo_rls.db" };
    
    println!("LibSQL Row Level Security (RLS) Demo");
    println!("====================================");
    
    // Always delete and recreate the database for a fresh start
    if Path::new(db_path).exists() {
        std::fs::remove_file(db_path).expect("Failed to remove existing database file");
        println!("Removed existing database file for a fresh start");
    }
    
    println!("Setting up new database: {}\n", db_path);
    
    // Create and set up the database
    let db = Database::open(db_path)?;
    let conn = db.connect()?;
    
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
    
    // Create posts table for more complex testing
    conn.execute(
        "CREATE TABLE posts (
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            user_id INTEGER NOT NULL,
            tenant_id INTEGER NOT NULL
        )",
        params![],
    ).await?;
    
    // Insert test posts
    conn.execute(
        "INSERT INTO posts (id, title, content, user_id, tenant_id) VALUES
        (1, 'Alice Post 1', 'Content from Alice', 1, 100),
        (2, 'Alice Post 2', 'More content from Alice', 1, 100),
        (3, 'Bob Post', 'Content from Bob', 2, 100),
        (4, 'Charlie Post', 'Content from Charlie', 3, 200),
        (5, 'Dave Post', 'Content from Dave', 4, 200)",
        params![],
    ).await?;
    
    // Create RLS connection
    let rls_conn = RlsConnection::new_initialized(conn).await?;
    
    // Create a default policy for tenant isolation (to demonstrate RLS)
    rls_conn.execute(
        "CREATE POLICY tenant_isolation ON users USING (tenant_id = 100)",
        params![],
    ).await?;
    
    rls_conn.execute(
        "CREATE POLICY tenant_posts ON posts USING (tenant_id = 100)",
        params![],
    ).await?;
    
    println!("Database initialized with sample data and default policies");
    
    // Display available tables
    println!("\nAvailable tables:");
    let tables = get_tables(&rls_conn).await?;
    for table in &tables {
        println!("- {}", table);
    }
    
    // Display policies
    println!("\nActive RLS Policies:");
    let mut rows = rls_conn.query(
        "SELECT name, table_name, using_expr FROM _rls_policies",
        params![],
    ).await?;
    
    while let Some(row) = rows.next()? {
        println!(
            "- {} on table {}: {}",
            row.get::<String>(0)?,
            row.get::<String>(1)?,
            row.get::<Option<String>>(2)?.unwrap_or_default()
        );
    }
    
    // Print special commands that are supported
    println!("\n=== Interactive SQL Mode ===");
    println!("Enter SQL queries to execute with RLS applied");
    println!("\nSpecial commands:");
    println!("- CREATE POLICY <name> ON <table> USING (<expression>)");
    println!("- SHOW POLICIES");
    println!("- RESET POLICIES <table>");
    println!("- exit/quit - Exit the REPL");
    println!("\nDemo Flow:");
    println!("1. Try 'SELECT * FROM users;' (note tenant_id = 100 filter applied)");
    println!("2. Add a new policy: 'CREATE POLICY user_filter ON users USING (id = 1)'");
    println!("3. Try 'SELECT * FROM users;' again (notice only user with id = 1 is shown)");
    
    let mut input = String::new();
    loop {
        print!("\nsql> ");
        io::stdout().flush().unwrap();
        
        input.clear();
        io::stdin().read_line(&mut input).unwrap();
        let input = input.trim();
        
        if input.eq_ignore_ascii_case("exit") || input.eq_ignore_ascii_case("quit") {
            break;
        }
        
        if input.is_empty() {
            continue;
        }
        
        // Handle special commands
        if input.to_uppercase().starts_with("CREATE POLICY") {
            // This is a policy creation statement, pass it directly to execute
            match rls_conn.execute(input, params![]).await {
                Ok(rows_affected) => {
                    println!("Policy created successfully ({} rows affected)", rows_affected);
                },
                Err(e) => {
                    println!("Error creating policy: {}", e);
                }
            }
            continue;
        } else if input.to_uppercase() == "SHOW POLICIES" {
            // Show all policies
            match rls_conn.query(
                "SELECT name, table_name, using_expr FROM _rls_policies", 
                params![]
            ).await {
                Ok(mut rows) => {
                    println!("\nCurrent policies:");
                    let mut count = 0;
                    while let Some(row) = rows.next()? {
                        count += 1;
                        println!(
                            "- {} on table {}: {}", 
                            row.get::<String>(0)?,
                            row.get::<String>(1)?,
                            row.get::<Option<String>>(2)?.unwrap_or_default()
                        );
                    }
                    if count == 0 {
                        println!("No policies defined");
                    }
                },
                Err(e) => {
                    println!("Error retrieving policies: {}", e);
                }
            }
            continue;
        } else if input.to_uppercase().starts_with("RESET POLICIES") {
            // Reset policies for a specific table
            let parts: Vec<&str> = input.splitn(3, ' ').collect();
            if parts.len() != 3 {
                println!("Usage: RESET POLICIES <table_name>");
                continue;
            }
            
            let table_name = parts[2];
            match rls_conn.execute(
                "DELETE FROM _rls_policies WHERE table_name = ?", 
                params![table_name]
            ).await {
                Ok(rows_affected) => {
                    println!("Policies reset for table {} ({} policies removed)", table_name, rows_affected);
                },
                Err(e) => {
                    println!("Error resetting policies: {}", e);
                }
            }
            continue;
        }
        
        // Execute regular SQL query with RLS applied
        match rls_conn.query(input, params![]).await {
            Ok(mut rows) => {
                let mut count = 0;
                println!("\nResults:");
                
                // Very simple output, just print each row
                while let Some(row) = rows.next()? {
                    count += 1;
                    println!("Row {}: {:?}", count, row);
                }
                
                println!("\n{} row(s) returned", count);
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
    }
    
    println!("Goodbye!");
    
    Ok(())
}

// Helper function to get the list of tables
async fn get_tables(rls_conn: &RlsConnection) -> Result<Vec<String>> {
    let mut tables = Vec::new();
    let mut rows = rls_conn.query(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_rls_%'",
        params![]
    ).await?;
    
    while let Some(row) = rows.next()? {
        tables.push(row.get::<String>(0)?);
    }
    
    Ok(tables)
} 