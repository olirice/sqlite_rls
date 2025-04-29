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

use anyhow::{Result, Context};
use async_trait::async_trait;
use libsql::Database;
use std::sync::Arc;

use crate::compat::DatabaseWrapper;
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
        
        // Verify tables exist
        println!("RLS: Verifying tables exist...");
        let mut tables_row = conn.query(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_tables'",
            compat::empty_params(),
        ).await.context("Failed to verify _rls_tables existence")?;
        
        let mut exists = false;
        let mut row_count = 0;
        while let Some(_) = tables_row.next().await? {
            exists = true;
            row_count += 1;
        }
        
        if exists {
            println!("RLS: _rls_tables verified to exist ({} rows)", row_count);
        } else {
            println!("RLS: _rls_tables NOT found in sqlite_master!");
        }
        
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