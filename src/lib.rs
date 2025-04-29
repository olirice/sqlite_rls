//! libSQL Row Level Security Extension
//!
//! This library implements PostgreSQL-like Row Level Security for libSQL databases.
//! It works by manipulating SQL Abstract Syntax Trees (ASTs) to apply security policies.

pub mod ast;
pub mod error;
pub mod parser;
pub mod policy;
pub mod rewriter;
pub mod compat;

use anyhow::{Result, Context, anyhow};
use async_trait::async_trait;
use libsql::{Database, Connection, Builder};
use sqlparser::ast::Statement;
use std::sync::Arc;

use crate::compat::{DatabaseWrapper, ConnectionExt};
use crate::policy::PolicyManager;
use crate::rewriter::QueryRewriter;

/// Reexports important types and traits for easy use
pub mod prelude {
    // Re-export from the crate
    pub use crate::compat::{DatabaseWrapper, ConnectionExt, IntoParams};
    pub use crate::error::Error;
    pub use crate::parser::Parser;
    pub use crate::policy::{Policy, PolicyManager};
    pub use crate::rewriter::QueryRewriter;
    pub use crate::RlsExtension;
    pub use crate::RlsExt;
}

/// Extension trait for libSQL to add Row Level Security
#[async_trait]
pub trait RlsExt {
    /// Initialize the RLS extension
    async fn initialize(&mut self) -> Result<()>;

    /// Get a query rewriter to transform SQL based on RLS policies
    fn rewriter(&self) -> QueryRewriter;
    
    /// Get the database wrapper reference for external use
    fn wrapper(&self) -> &DatabaseWrapper;
}

/// The main extension struct for Row Level Security
pub struct RlsExtension {
    wrapper: DatabaseWrapper,
}

impl RlsExtension {
    /// Create a new RLS extension with the given database
    pub fn new(database: Arc<Database>) -> Self {
        let wrapper = DatabaseWrapper::new(database);
        Self {
            wrapper,
        }
    }
    
    /// Initialize a new RLS extension from a connection
    pub async fn init(conn: &Connection, _context: &str) -> Result<Self> {
        println!("RLS: Initializing from connection...");
        
        // Create a new extension using a new database connection
        // Since we can't get the database from the connection directly,
        // we'll create a new in-memory database for the extension
        let database = Builder::new_local(":memory:")
            .build()
            .await
            .context("Failed to create in-memory database")?;
        
        let database_arc = Arc::new(database);
        
        // Create the extension
        let mut extension = Self::new(database_arc);
        
        // Initialize the extension - this will create the RLS metadata tables
        extension.initialize().await?;
        
        // Create the _rls_current_user table if it doesn't exist
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _rls_current_user (id TEXT, role TEXT)",
            compat::empty_params(),
        ).await.context("Failed to create _rls_current_user table")?;
        
        println!("RLS: Initialization from connection complete");
        Ok(extension)
    }
    
    /// Check if the RLS tables exist and have valid schema
    async fn check_and_validate_schema(&self, conn: &Connection) -> Result<bool> {
        // Check if tables exist in sqlite_master
        let tables_exist = conn.query_all(
            "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('_rls_tables', '_rls_policies')",
            compat::empty_params(),
        ).await?;
        
        if tables_exist.len() != 2 {
            println!("RLS: Not all required tables exist ({}/2 found)", tables_exist.len());
            return Ok(true); // Need to rebuild
        }
        
        // Verify _rls_tables schema
        let tables_schema = conn.query_all(
            "PRAGMA table_info(_rls_tables)",
            compat::empty_params(),
        ).await?;
        
        if tables_schema.len() != 2 {
            println!("RLS: _rls_tables schema is invalid (has {} columns, expected 2)", tables_schema.len());
            return Ok(true); // Need to rebuild
        }
        
        let col0_name: Result<String, _> = tables_schema[0].get(1);
        let col1_name: Result<String, _> = tables_schema[1].get(1);
        
        if col0_name.is_err() || col1_name.is_err() || 
           col0_name.as_ref().map(|s| s != "table_name").unwrap_or(true) ||
           col1_name.as_ref().map(|s| s != "enabled").unwrap_or(true) {
            println!("RLS: _rls_tables column names are invalid");
            return Ok(true); // Need to rebuild
        }
        
        // Verify _rls_policies schema
        let policies_schema = conn.query_all(
            "PRAGMA table_info(_rls_policies)",
            compat::empty_params(),
        ).await?;
        
        println!("RLS: _rls_policies schema columns: {}", policies_schema.len());
        for (i, row) in policies_schema.iter().enumerate() {
            let name: Result<String, _> = row.get(1);
            let type_str: Result<String, _> = row.get(2);
            let notnull: Result<i64, _> = row.get(3);
            let dflt: Result<Option<String>, _> = row.get(4);
            let pk: Result<i64, _> = row.get(5);
            
            println!("RLS: Column {}: name={:?}, type={:?}, notnull={:?}, default={:?}, pk={:?}",
                i, name, type_str, notnull, dflt, pk);
        }
        
        if policies_schema.len() != 5 {
            println!("RLS: _rls_policies schema is invalid (has {} columns, expected 5)", policies_schema.len());
            return Ok(true); // Need to rebuild
        }
        
        let expected_columns = ["policy_name", "table_name", "operation", "using_expr", "check_expr"];
        
        for (i, expected) in expected_columns.iter().enumerate() {
            let col_name: Result<String, _> = policies_schema[i].get(1);
            if col_name.is_err() || col_name.as_ref().map(|s| s != expected).unwrap_or(true) {
                println!("RLS: _rls_policies column {} name is invalid (expected '{}', got '{:?}')", 
                        i, expected, col_name);
                return Ok(true); // Need to rebuild
            }
        }
        
        // Verify foreign key is setup correctly
        let fk_check = conn.query_all(
            "PRAGMA foreign_key_list(_rls_policies)",
            compat::empty_params(),
        ).await?;
        
        if fk_check.is_empty() {
            println!("RLS: _rls_policies missing foreign key constraint");
            return Ok(true); // Need to rebuild
        }
        
        println!("RLS: Schema validation passed");
        Ok(false) // No need to rebuild
    }
}

#[async_trait]
impl RlsExt for RlsExtension {
    /// Initialize the RLS extension
    async fn initialize(&mut self) -> Result<()> {
        // Create the RLS metadata tables if they don't exist
        println!("RLS: Starting initialization...");
        
        // Get a direct connection to the database
        let conn = self.wrapper.inner().connect().context("Failed to connect to database")?;
        println!("RLS: Connected to database successfully");
        
        // Check if tables exist and have valid schema
        let need_rebuild = self.check_and_validate_schema(&conn).await?;
        
        if need_rebuild {
            println!("RLS: Schema validation failed - rebuilding tables...");
            // Drop existing tables
            conn.execute("DROP TABLE IF EXISTS _rls_policies", compat::empty_params()).await
                .context("Failed to drop _rls_policies")?;
            conn.execute("DROP TABLE IF EXISTS _rls_tables", compat::empty_params()).await
                .context("Failed to drop _rls_tables")?;
        }
        
        // Tables table - tracks which tables have RLS enabled
        println!("RLS: Creating _rls_tables...");
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _rls_tables (
                table_name TEXT PRIMARY KEY,
                enabled BOOLEAN NOT NULL DEFAULT 0
            )",
            compat::empty_params(),
        ).await.context("Failed to create _rls_tables")?;
        println!("RLS: _rls_tables created successfully");
        
        // Policies table - stores RLS policies
        println!("RLS: Creating _rls_policies...");
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
            compat::empty_params(),
        ).await.context("Failed to create _rls_policies")?;
        println!("RLS: _rls_policies created successfully");
        
        // After we've created the tables but before inserting the test policy, run an integrity check
        println!("RLS: Running database integrity check...");
        match conn.query_all("PRAGMA integrity_check", compat::empty_params()).await {
            Ok(rows) => {
                if rows.len() > 0 {
                    let result = rows[0].get::<String>(0).unwrap_or_default();
                    if result == "ok" {
                        println!("RLS: Database integrity check passed.");
                    } else {
                        println!("RLS: Database integrity check FAILED: {}", result);
                    }
                } else {
                    println!("RLS: Database integrity check returned no rows!");
                }
            },
            Err(e) => {
                println!("RLS: Database integrity check ERROR: {:?}", e);
            }
        }

        // Test SQLite version
        println!("RLS: Checking SQLite version...");
        match conn.query_row("SELECT sqlite_version()", compat::empty_params()).await {
            Ok(Some(row)) => {
                let version = row.get::<String>(0).unwrap_or_default();
                println!("RLS: SQLite version: {}", version);
            },
            _ => println!("RLS: Could not determine SQLite version"),
        }

        // Verify the SQLite compilation options
        println!("RLS: Checking SQLite compilation options...");
        match conn.query_all("PRAGMA compile_options", compat::empty_params()).await {
            Ok(rows) => {
                println!("RLS: SQLite compile options:");
                for row in rows {
                    let option = row.get::<String>(0).unwrap_or_default();
                    println!("RLS:   {}", option);
                }
            },
            Err(e) => {
                println!("RLS: Error getting SQLite compilation options: {:?}", e);
            }
        }

        // Verify creation was successful by inserting a test policy
        println!("RLS: Verifying tables were created correctly...");
        
        // First add the test table to _rls_tables 
        match conn.execute(
            "INSERT OR REPLACE INTO _rls_tables (table_name, enabled) VALUES ('test_table', 1)",
            compat::empty_params(),
        ).await {
            Ok(_) => println!("RLS: Test table added to _rls_tables successfully"),
            Err(e) => println!("RLS: Error adding test table: {:?}", e),
        };
        
        // Now insert a test policy - using direct SQL format with explicit string literals
        println!("RLS: Testing policy insertion...");
        let test_policy_sql = 
            "INSERT OR REPLACE INTO _rls_policies (policy_name, table_name, operation, using_expr, check_expr) 
            VALUES ('test_policy', 'test_table', 'SELECT', 'true', NULL)";
        
        println!("RLS: Test policy SQL: {}", test_policy_sql);
        let test_result = conn.execute(test_policy_sql, compat::empty_params()).await;
        
        match test_result {
            Ok(_) => println!("RLS: Test policy insertion succeeded"),
            Err(e) => {
                println!("RLS: Test policy insertion failed: {:?}", e);
                return Err(anyhow!("Failed to insert test policy: {:?}", e));
            }
        }
        
        // Verify the insertion and make sure we can read the data correctly
        println!("RLS: Verifying test policy insertion...");
        
        // Dump the entire _rls_policies table to see what got inserted
        println!("RLS: Dumping _rls_policies table content:");
        let all_policies_sql = "SELECT * FROM _rls_policies";
        match conn.query_all(all_policies_sql, compat::empty_params()).await {
            Ok(rows) => {
                println!("RLS: Found {} total policies in table", rows.len());
                for (i, row) in rows.iter().enumerate() {
                    println!("RLS: Policy row {}: {:?}", i, row);
                    // Try different ways to access the data
                    for col in 0..5 {
                        let col_name = match col {
                            0 => "policy_name",
                            1 => "table_name",
                            2 => "operation",
                            3 => "using_expr",
                            4 => "check_expr",
                            _ => "unknown"
                        };
                        
                        let as_string = row.get::<String>(col);
                        let as_opt = row.get::<Option<String>>(col);
                        let as_value = row.get::<libsql::Value>(col);
                        
                        println!("RLS:   Column {} ({}): as String = {:?}, as Option<String> = {:?}, as Value = {:?}",
                                col, col_name, as_string, as_opt, as_value);
                    }
                }
            },
            Err(e) => {
                println!("RLS: Error dumping _rls_policies: {:?}", e);
            }
        }
        
        // Try both query methods - direct SQL and parameterized
        println!("RLS: Testing with direct SQL...");
        let test_rows_direct = conn.query_all(
            "SELECT policy_name, table_name, operation, using_expr, check_expr FROM _rls_policies WHERE policy_name = 'test_policy'",
            compat::empty_params(),
        ).await.context("Failed to verify test policy with direct SQL")?;
        
        println!("RLS: Direct SQL found {} test policy rows", test_rows_direct.len());
        
        if !test_rows_direct.is_empty() {
            let row = &test_rows_direct[0];
            // Dump the entire row to see what we're working with
            println!("RLS:   Row debug: {:?}", row);
            
            // Try to access each column index
            for col in 0..5 {
                let val_text: Result<String, _> = row.get(col);
                let val_opt: Result<Option<String>, _> = row.get(col);
                println!("RLS:   Column {} as String: {:?}, as Option<String>: {:?}", 
                         col, val_text, val_opt);
            }
        }
        
        println!("RLS: Testing with parameterized query...");
        let test_rows_params = conn.query_all(
            "SELECT policy_name, table_name, operation, using_expr, check_expr FROM _rls_policies WHERE policy_name = ?",
            "test_policy",
        ).await.context("Failed to verify test policy with parameterized query")?;
        
        println!("RLS: Parameterized query found {} test policy rows", test_rows_params.len());
        
        // Verify we can read the policy using either query method
        let combined_rows = if !test_rows_direct.is_empty() {
            &test_rows_direct
        } else if !test_rows_params.is_empty() {
            &test_rows_params
        } else {
            return Err(anyhow!("Test policy not found after insertion"));
        };
        
        if !combined_rows.is_empty() {
            let row = &combined_rows[0];
            
            // Try different types for getting data from columns
            println!("RLS: Testing different types for reading columns");
            
            // As String
            let policy_name: Result<String, _> = row.get(0);
            let table_name: Result<String, _> = row.get(1);
            let operation: Result<String, _> = row.get(2);
            
            println!("RLS:   policy_name as String = {:?}", policy_name);
            println!("RLS:   table_name as String = {:?}", table_name);
            println!("RLS:   operation as String = {:?}", operation);
            
            // As Option<String>
            let policy_name_opt: Result<Option<String>, _> = row.get(0);
            let table_name_opt: Result<Option<String>, _> = row.get(1);
            let operation_opt: Result<Option<String>, _> = row.get(2);
            
            println!("RLS:   policy_name as Option<String> = {:?}", policy_name_opt);
            println!("RLS:   table_name as Option<String> = {:?}", table_name_opt);
            println!("RLS:   operation as Option<String> = {:?}", operation_opt);
            
            // As Value
            let policy_name_val: Result<libsql::Value, _> = row.get(0);
            let table_name_val: Result<libsql::Value, _> = row.get(1);
            let operation_val: Result<libsql::Value, _> = row.get(2);
            
            println!("RLS:   policy_name as Value = {:?}", policy_name_val);
            println!("RLS:   table_name as Value = {:?}", table_name_val);
            println!("RLS:   operation as Value = {:?}", operation_val);
            
            // If all attempts to read as String failed, this is likely a database issue
            if policy_name.is_err() && table_name.is_err() && operation.is_err() &&
               policy_name_opt.is_err() && table_name_opt.is_err() && operation_opt.is_err() {
                println!("RLS: ERROR - Cannot read policy data correctly with any method");
                println!("RLS: This appears to be a database storage or retrieval issue.");
                return Err(anyhow!("Cannot read policy data correctly"));
            }
        }
        
        // Clean up the test policy
        conn.execute(
            "DELETE FROM _rls_policies WHERE policy_name = 'test_policy'",
            compat::empty_params(),
        ).await.context("Failed to delete test policy")?;
        
        conn.execute(
            "DELETE FROM _rls_tables WHERE table_name = 'test_table'",
            compat::empty_params(),
        ).await.context("Failed to delete test table")?;
        
        println!("RLS: Initialization complete");
        Ok(())
    }

    /// Get a query rewriter for this extension
    fn rewriter(&self) -> QueryRewriter {
        let db_arc = self.wrapper.inner();
        let policy_manager = PolicyManager::new(db_arc.clone());
        QueryRewriter::new(db_arc, policy_manager)
    }
    
    /// Get the database wrapper for external use
    fn wrapper(&self) -> &DatabaseWrapper {
        &self.wrapper
    }
} 