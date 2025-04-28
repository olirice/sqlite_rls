use anyhow::{Result, Context, anyhow};
use clap::Parser;
use std::io::{self, Write};
use std::path::PathBuf;
use env_logger::Env;
use libsql::Database;
use libsql_rls::prelude::*;
use libsql_rls::parser::{Parser as RlsParser, RlsStatement};

#[derive(Parser, Debug)]
#[clap(author, version, about = "libSQL interactive shell with Row Level Security support")]
struct Cli {
    /// Path to SQLite database file
    #[clap(value_parser)]
    database_path: Option<PathBuf>,

    /// Current user for RLS context
    #[clap(short, long, default_value = "admin")]
    user: String,

    /// Enable debug logging
    #[clap(short, long)]
    debug: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Initialize logger
    let env = if cli.debug {
        Env::default().default_filter_or("debug")
    } else {
        Env::default().default_filter_or("info")
    };
    env_logger::init_from_env(env);
    
    // Open database
    let db_path = cli.database_path.unwrap_or_else(|| PathBuf::from(":memory:"));
    let db_url = if db_path.to_string_lossy() == ":memory:" {
        "file::memory:?mode=memory&cache=shared".to_string()
    } else {
        format!("file:{}", db_path.display())
    };
    
    println!("Opening database: {}", db_url);
    let database = Database::open(&db_url).context("Failed to open database")?;
    
    // Set up the current user for RLS context
    let conn = database.connect()?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _rls_current_user (user_id TEXT NOT NULL)",
        ()
    ).await?;
    
    conn.execute("DELETE FROM _rls_current_user", ()).await?;
    conn.execute(
        "INSERT INTO _rls_current_user (user_id) VALUES (?)",
        [&cli.user]
    ).await?;
    
    // Create a user-defined function to get the current user
    conn.execute(
        "CREATE FUNCTION IF NOT EXISTS current_user() 
         RETURNS TEXT 
         AS 'SELECT user_id FROM _rls_current_user LIMIT 1'",
        ()
    ).await?;
    
    // Initialize the RLS extension
    let rls = RlsExtension::new(database.clone());
    rls.initialize().await?;
    
    println!("libSQL shell with Row Level Security");
    println!("Current user: {}", cli.user);
    println!("Enter SQL queries or RLS statements, or type '.help' for commands");
    
    let parser = RlsParser::new();
    
    // Main REPL loop
    loop {
        print!("sql> ");
        io::stdout().flush()?;
        
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();
        
        if input.is_empty() {
            continue;
        }
        
        // Handle special commands
        if input.starts_with('.') {
            match input {
                ".exit" | ".quit" => break,
                ".help" => {
                    println!("Commands:");
                    println!(".exit, .quit - Exit the shell");
                    println!(".help - Display this help message");
                    println!(".user USERNAME - Change the current user");
                    println!();
                    println!("RLS Statements:");
                    println!("ALTER TABLE tablename ENABLE ROW LEVEL SECURITY");
                    println!("ALTER TABLE tablename DISABLE ROW LEVEL SECURITY");
                    println!("CREATE POLICY policyname ON tablename FOR operation USING (expression)");
                    println!("DROP POLICY policyname ON tablename");
                }
                s if s.starts_with(".user ") => {
                    let new_user = s.trim_start_matches(".user ").trim();
                    if new_user.is_empty() {
                        println!("Error: User name cannot be empty");
                        continue;
                    }
                    
                    conn.execute("DELETE FROM _rls_current_user", ()).await?;
                    conn.execute(
                        "INSERT INTO _rls_current_user (user_id) VALUES (?)",
                        [new_user]
                    ).await?;
                    
                    println!("Current user set to: {}", new_user);
                }
                _ => {
                    println!("Unknown command: {}", input);
                }
            }
            continue;
        }
        
        // Try to parse as an RLS-specific statement
        match parser.parse_rls_statement(input) {
            Ok(rls_stmt) => {
                // Handle RLS-specific statements
                match rls_stmt {
                    RlsStatement::AlterTableRls { table_name, enable } => {
                        let policy_manager = libsql_rls::policy::PolicyManager::new(database.clone());
                        policy_manager.set_rls_enabled(&table_name, enable).await?;
                        
                        if enable {
                            println!("RLS enabled on table '{}'", table_name);
                        } else {
                            println!("RLS disabled on table '{}'", table_name);
                        }
                    },
                    RlsStatement::CreatePolicy { policy_name, table_name, operation, using_expr, check_expr } => {
                        let policy = libsql_rls::policy::Policy::new(
                            policy_name.clone(),
                            table_name.clone(),
                            operation,
                            using_expr,
                            check_expr,
                        );
                        
                        let policy_manager = libsql_rls::policy::PolicyManager::new(database.clone());
                        policy_manager.create_policy(&policy).await?;
                        
                        println!("Created policy '{}' on table '{}'", policy_name, table_name);
                    },
                    RlsStatement::DropPolicy { policy_name, table_name } => {
                        let policy_manager = libsql_rls::policy::PolicyManager::new(database.clone());
                        policy_manager.drop_policy(&policy_name, &table_name).await?;
                        
                        println!("Dropped policy '{}' on table '{}'", policy_name, table_name);
                    }
                }
            },
            Err(_) => {
                // Handle regular SQL queries with RLS applied
                match rls.execute(input).await {
                    Ok(stmt) => {
                        // Execute the statement
                        match stmt.query_all(()).await {
                            Ok(rows) => {
                                // Display column names
                                if !rows.is_empty() {
                                    let row = &rows[0];
                                    let column_count = row.column_count();
                                    
                                    for i in 0..column_count {
                                        if i > 0 {
                                            print!(" | ");
                                        }
                                        print!("{}", row.column_name(i)?);
                                    }
                                    println!();
                                    
                                    // Print a separator
                                    for i in 0..column_count {
                                        if i > 0 {
                                            print!("-+-");
                                        }
                                        print!("{}", "-".repeat(row.column_name(i)?.len()));
                                    }
                                    println!();
                                }
                                
                                // Display rows
                                for row in rows {
                                    let column_count = row.column_count();
                                    
                                    for i in 0..column_count {
                                        if i > 0 {
                                            print!(" | ");
                                        }
                                        
                                        match row.get_value(i)? {
                                            Some(libsql::Value::Null) => print!("NULL"),
                                            Some(libsql::Value::Integer(i)) => print!("{}", i),
                                            Some(libsql::Value::Real(f)) => print!("{}", f),
                                            Some(libsql::Value::Text(s)) => print!("{}", s),
                                            Some(libsql::Value::Blob(b)) => print!("{:?}", b),
                                            None => print!("NULL"),
                                        }
                                    }
                                    println!();
                                }
                                
                                // Display row count
                                println!("{} row(s) returned", rows.len());
                            },
                            Err(e) => {
                                println!("Error executing query: {}", e);
                            }
                        }
                    },
                    Err(e) => {
                        println!("Error: {}", e);
                    }
                }
            }
        }
    }
    
    println!("Goodbye!");
    Ok(())
} 