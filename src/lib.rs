//! libSQL Row Level Security Extension
//!
//! This library implements PostgreSQL-like Row Level Security for libSQL databases.
//! It works by manipulating SQL Abstract Syntax Trees (ASTs) to apply security policies.

pub mod ast;
pub mod parser;
pub mod policy;
pub mod rewriter;
pub mod error;

use libsql::Database;
use anyhow::Result;

/// Main entry point for the libSQL RLS extension
pub struct RlsExtension {
    database: Database,
}

impl RlsExtension {
    /// Create a new RLS extension for the given database
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    /// Initialize the RLS extension, setting up required metadata tables
    pub async fn initialize(&self) -> Result<()> {
        // Create the metadata tables needed for RLS
        self.create_metadata_tables().await?;
        Ok(())
    }

    /// Create the metadata tables needed for RLS
    async fn create_metadata_tables(&self) -> Result<()> {
        let conn = self.database.connect()?;
        
        // Table to track which tables have RLS enabled
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _rls_tables (
                table_name TEXT PRIMARY KEY,
                enabled BOOLEAN NOT NULL DEFAULT FALSE
            )",
            (),
        ).await?;

        // Table to store RLS policies
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _rls_policies (
                id INTEGER PRIMARY KEY,
                policy_name TEXT NOT NULL,
                table_name TEXT NOT NULL,
                operation TEXT NOT NULL,
                using_expr TEXT,
                check_expr TEXT,
                UNIQUE(policy_name, table_name),
                FOREIGN KEY(table_name) REFERENCES _rls_tables(table_name) ON DELETE CASCADE
            )",
            (),
        ).await?;

        Ok(())
    }

    /// Execute a query with RLS applied
    pub async fn execute(&self, sql: &str) -> Result<libsql::Statement> {
        // Parse the SQL to an AST
        let ast = self.parse_sql(sql)?;
        
        // Apply RLS transformations to the AST
        let transformed_ast = self.apply_rls(ast).await?;
        
        // Convert the AST back to SQL
        let transformed_sql = self.ast_to_sql(transformed_ast)?;
        
        // Execute the transformed SQL
        let stmt = self.database.connect()?.prepare(&transformed_sql).await?;
        
        Ok(stmt)
    }

    // Parse SQL to AST
    fn parse_sql(&self, sql: &str) -> Result<sqlparser::ast::Statement> {
        self.parser().parse_sql(sql)
    }

    // Apply RLS transformations to the AST
    async fn apply_rls(&self, ast: sqlparser::ast::Statement) -> Result<sqlparser::ast::Statement> {
        let rewriter = self.rewriter().with_policy_manager(self.database.clone());
        rewriter.rewrite(ast).await
    }

    // Convert AST back to SQL
    fn ast_to_sql(&self, ast: sqlparser::ast::Statement) -> Result<String> {
        Ok(ast.to_string())
    }

    // Get a parser instance
    fn parser(&self) -> parser::Parser {
        parser::Parser::new()
    }

    // Get a rewriter instance
    fn rewriter(&self) -> rewriter::Rewriter {
        rewriter::Rewriter::new()
    }
}

/// A prelude of commonly used types
pub mod prelude {
    pub use crate::RlsExtension;
    pub use crate::error::Error;
    pub use anyhow::{Result, Context};
} 