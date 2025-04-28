use anyhow::{Result, Context, anyhow};
use clap::Parser;
use std::io::{self, Write};
use std::path::PathBuf;
use env_logger::Env;
use libsql::{Database, Builder, Connection};
use rls::prelude::*;
use rls::parser::{Parser as RlsParser, RlsStatement};
use rls::compat::{ConnectionExt, empty_params};
use std::sync::Arc;
use rustyline::error::ReadlineError;
use rustyline::Editor;
use rls::RlsExtension;
use sqlparser::ast::Statement;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(help = "Path to the database file")]
    db_path: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    
    let db_path = args.db_path.unwrap_or_else(|| ":memory:".to_string());
    println!("Opening database at: {}", db_path);
    
    let database = libsql::Builder::new_local(&db_path)
        .build()
        .await?;
    let conn = database.connect()?;
    
    // Initialize RLS extension
    let db_arc = Arc::new(database);
    let mut rls = RlsExtension::new(db_arc.clone());
    rls.initialize().await?;
    println!("RLS Extension initialized");
    
    let mut rl = Editor::<()>::new()?;
    let _ = rl.load_history("history.txt");
    
    println!("Row Level Security Shell");
    println!("Enter SQL queries or RLS commands");
    println!("RLS Commands:");
    println!("  ALTER TABLE <table> ENABLE ROW LEVEL SECURITY;");
    println!("  ALTER TABLE <table> DISABLE ROW LEVEL SECURITY;");
    println!("  CREATE POLICY <n> ON <table> FOR <SELECT|INSERT|UPDATE|DELETE> USING (<expr>) [WITH CHECK (<expr>)];");
    println!("  DROP POLICY <n> ON <table>;");
    println!("Type 'exit' or Ctrl-D to exit");
    
    // Set up a _current_user table for context
    let _ = conn.execute(
        "CREATE TABLE IF NOT EXISTS _rls_current_user (id TEXT, role TEXT)",
        empty_params(),
    ).await;
    
    // Check if there's a current user set
    let rows = conn.query_all(
        "SELECT id, role FROM _rls_current_user LIMIT 1",
        empty_params(),
    ).await?;
    
    if rows.is_empty() {
        println!("No current user set. Use SET_USER(<id>, <role>) to set one.");
    } else {
        let row = &rows[0];
        println!("Current user: {} (role: {})", 
                 row.get::<String>(0)?,
                 row.get::<String>(1)?);
    }
    
    // Set up helper function for setting the current user
    conn.execute(
        "CREATE FUNCTION IF NOT EXISTS SET_USER(id TEXT, role TEXT) AS
         BEGIN
           DELETE FROM _rls_current_user;
           INSERT INTO _rls_current_user VALUES ($id, $role);
           SELECT 'Current user set to ' || $id || ' with role ' || $role;
         END;",
        empty_params(),
    ).await?;
    
    // Set up helper function for getting the current user
    conn.execute(
        "CREATE FUNCTION IF NOT EXISTS CURRENT_USER() 
         RETURNS TEXT AS
         'SELECT id FROM _rls_current_user LIMIT 1'",
        empty_params(),
    ).await?;
    
    // Set up helper function for getting the current role
    conn.execute(
        "CREATE FUNCTION IF NOT EXISTS CURRENT_ROLE() 
         RETURNS TEXT AS
         'SELECT role FROM _rls_current_user LIMIT 1'",
        empty_params(),
    ).await?;
    
    loop {
        let readline = rl.readline("sql> ");
        match readline {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                
                let _ = rl.add_history_entry(&line);
                let input = line.trim();
                
                if input.eq_ignore_ascii_case("exit") {
                    break;
                }
                
                // Try to parse as an RLS statement
                let parser = RlsParser::new();
                // First try to parse as RLS-specific statement
                match parser.parse_rls_statement(input) {
                    Ok(rls_stmt) => {
                        // Handle RLS statement
                        match rls_stmt {
                            RlsStatement::AlterTableRls { table_name, enable } => {
                                let policy_manager = rls::policy::PolicyManager::new(db_arc.clone());
                                policy_manager.set_rls_enabled(&table_name, enable).await?;
                                
                                if enable {
                                    println!("RLS enabled on table '{}'", table_name);
                                } else {
                                    println!("RLS disabled on table '{}'", table_name);
                                }
                            },
                            RlsStatement::CreatePolicy { policy_name, table_name, operation, using_expr, check_expr } => {
                                let policy = rls::policy::Policy::new(
                                    policy_name.clone(),
                                    table_name.clone(),
                                    operation,
                                    using_expr,
                                    check_expr,
                                );
                                
                                let policy_manager = rls::policy::PolicyManager::new(db_arc.clone());
                                policy_manager.create_policy(&policy).await?;
                                
                                println!("Created policy '{}' on table '{}'", policy_name, table_name);
                            },
                            RlsStatement::DropPolicy { policy_name, table_name } => {
                                let policy_manager = rls::policy::PolicyManager::new(db_arc.clone());
                                policy_manager.drop_policy(&policy_name, &table_name).await?;
                                
                                println!("Dropped policy '{}' on table '{}'", policy_name, table_name);
                            }
                        }
                    },
                    Err(_) => {
                        // Try to parse as regular SQL
                        let dialect = sqlparser::dialect::SQLiteDialect{};
                        let ast = sqlparser::parser::Parser::parse_sql(&dialect, input);
                        
                        match ast {
                            Ok(stmts) => {
                                if !stmts.is_empty() {
                                    // Use the first statement with RLS rewriter
                                    let rewriter = rls.rewriter();
                                    
                                    match rewriter.rewrite(stmts[0].clone()).await {
                                        Ok(rewritten_stmt) => {
                                            let rewritten_sql = rewritten_stmt.to_string();
                                            println!("Executing: {}", rewritten_sql);
                                            
                                            match conn.execute(&rewritten_sql, empty_params()).await {
                                                Ok(count) => println!("Success. Rows affected: {}", count),
                                                Err(e) => println!("Error: {}", e),
                                            }
                                        },
                                        Err(e) => println!("Error rewriting SQL: {}", e),
                                    }
                                } else {
                                    println!("Empty SQL statement");
                                }
                            },
                            Err(e) => println!("Error parsing SQL: {}", e),
                        }
                    }
                }
            },
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!("Exiting...");
                break;
            },
            Err(err) => {
                println!("Error: {}", err);
                break;
            }
        }
    }
    
    let _ = rl.save_history("history.txt");
    Ok(())
} 