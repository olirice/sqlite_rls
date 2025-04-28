use anyhow::Result;
use std::sync::Arc;
use libsql::{Database, Builder};
use sqlparser::ast::{self, Statement, TableFactor, TableWithJoins, Query, SetExpr};
use crate::ast::AstManipulator;
use crate::policy::PolicyManager;
use crate::parser::Parser;
use tokio::runtime::Runtime;
use crate::error::Error;
use crate::policy::{Policy, Operation};
use crate::parser::{RlsOperation};
use crate::compat::{ConnectionExt, DatabaseWrapper};
use sqlparser::dialect::SQLiteDialect;
use libsql::{Value, params};
use sqlparser::dialect::GenericDialect;
use sqlparser::ast::{Ident, BinaryOperator, Expr};

/// Handles rewriting SQL statements to apply RLS policies
pub struct QueryRewriter {
    database: Arc<Database>,
    ast_manipulator: AstManipulator,
    policy_manager: PolicyManager,
    parser: Parser,
}

impl QueryRewriter {
    /// Create a new rewriter
    pub fn new(database: Arc<Database>, policy_manager: PolicyManager) -> Self {
        Self {
            database,
            ast_manipulator: AstManipulator::new(),
            policy_manager,
            parser: Parser::new(),
        }
    }

    /// Rewrite a statement to apply RLS
    pub async fn rewrite(&self, stmt: Statement) -> Result<Statement> {
        match stmt {
            Statement::Query(query) => self.rewrite_select(*query).await.map(|q| Statement::Query(Box::new(q))),
            Statement::Insert { .. } => self.rewrite_insert(stmt).await,
            Statement::Update { .. } => self.rewrite_update(stmt).await,
            Statement::Delete { .. } => self.rewrite_delete(stmt).await,
            _ => Ok(stmt), // Pass through other statement types
        }
    }
    
    /// Rewrite a SELECT statement with RLS policies
    async fn rewrite_select(&self, query: Query) -> Result<Query> {
        let tables = self.extract_table_names_from_query(&query);
        
        // If no tables with RLS, return the original query
        let tables_with_rls = self.filter_tables_with_rls(&tables).await?;
        if tables_with_rls.is_empty() {
            return Ok(query);
        }
        
        // Generate the rewritten query with RLS conditions
        // For now, this is a simplified implementation
        // A real implementation would need to modify the query AST to add WHERE clauses
        // based on the RLS policies
        
        Ok(query) // Placeholder: return the original query
    }
    
    /// Extract table names from a query
    fn extract_table_names_from_query(&self, query: &Query) -> Vec<String> {
        let mut tables = Vec::new();
        
        // Extract tables from query
        match &*query.body {
            SetExpr::Select(select) => {
                for table_with_joins in &select.from {
                    if let TableFactor::Table { name, .. } = &table_with_joins.relation {
                        if !name.0.is_empty() {
                            // Get the last part of the name (e.g., "table" from "schema.table")
                            let table_name = name.0.last().unwrap().value.clone();
                            tables.push(table_name);
                        }
                    }
                    
                    // Also process joins
                    for join in &table_with_joins.joins {
                        if let TableFactor::Table { name, .. } = &join.relation {
                            if !name.0.is_empty() {
                                let table_name = name.0.last().unwrap().value.clone();
                                tables.push(table_name);
                            }
                        }
                    }
                }
            },
            _ => {}
        }
        
        tables
    }
    
    /// Rewrite an INSERT statement with RLS policies
    async fn rewrite_insert(&self, stmt: Statement) -> Result<Statement> {
        // Extract the table name
        let table_name = match &stmt {
            Statement::Insert { table_name, .. } => table_name.to_string(),
            _ => return Ok(stmt),
        };
        
        // Check if the table has RLS enabled
        if !self.table_has_rls(&table_name).await? {
            return Ok(stmt);
        }
        
        // Apply check policies for INSERT
        // A real implementation would modify the INSERT to include CHECKs based on RLS policies
        
        Ok(stmt) // Placeholder: return the original statement
    }
    
    /// Rewrite an UPDATE statement with RLS policies
    async fn rewrite_update(&self, stmt: Statement) -> Result<Statement> {
        // Extract the table name
        let table_name = match &stmt {
            Statement::Update { table, .. } => {
                match &table.relation {
                    TableFactor::Table { name, .. } => name.to_string(),
                    _ => return Ok(stmt),
                }
            },
            _ => return Ok(stmt),
        };
        
        // Check if the table has RLS enabled
        if !self.table_has_rls(&table_name).await? {
            return Ok(stmt);
        }
        
        // Apply USING and CHECK policies for UPDATE
        // A real implementation would modify the UPDATE to include WHERE and SET clauses
        // based on RLS policies
        
        Ok(stmt) // Placeholder: return the original statement
    }
    
    /// Rewrite a DELETE statement with RLS policies
    async fn rewrite_delete(&self, stmt: Statement) -> Result<Statement> {
        // Extract the table name
        let table_name = match &stmt {
            Statement::Delete { from, .. } => {
                if from.is_empty() {
                    return Ok(stmt);
                }
                
                let table_with_joins = &from[0];
                match &table_with_joins.relation {
                    TableFactor::Table { name, .. } => name.to_string(),
                    _ => return Ok(stmt),
                }
            },
            _ => return Ok(stmt),
        };
        
        // Check if the table has RLS enabled
        if !self.table_has_rls(&table_name).await? {
            return Ok(stmt);
        }
        
        // Apply USING policies for DELETE
        // A real implementation would modify the DELETE to include WHERE clauses
        // based on RLS policies
        
        Ok(stmt) // Placeholder: return the original statement
    }
    
    /// Extract table names from a statement
    fn extract_table_names(&self, stmt: &Statement) -> Vec<String> {
        let mut tables = Vec::new();
        
        match stmt {
            Statement::Query(query) => {
                tables.extend(self.extract_table_names_from_query(query));
            },
            Statement::Insert { table_name, .. } => {
                if !table_name.0.is_empty() {
                    tables.push(table_name.0.last().unwrap().value.clone());
                }
            },
            Statement::Update { table, .. } => {
                if let TableFactor::Table { name, .. } = &table.relation {
                    if !name.0.is_empty() {
                        tables.push(name.0.last().unwrap().value.clone());
                    }
                }
            },
            Statement::Delete { from, .. } => {
                if !from.is_empty() {
                    let table_with_joins = &from[0];
                    if let TableFactor::Table { name, .. } = &table_with_joins.relation {
                        if !name.0.is_empty() {
                            tables.push(name.0.last().unwrap().value.clone());
                        }
                    }
                }
            },
            _ => {
                // Other statements don't have tables to protect
            },
        }
        
        tables
    }

    /// Check if a table has RLS enabled
    async fn table_has_rls(&self, table_name: &str) -> Result<bool> {
        self.policy_manager.is_rls_enabled(table_name).await
    }

    /// Filter tables to only those with RLS enabled
    async fn filter_tables_with_rls(&self, tables: &[String]) -> Result<Vec<String>> {
        let mut result = Vec::new();
        
        for table in tables {
            if self.table_has_rls(table).await? {
                result.push(table.clone());
            }
        }
        
        Ok(result)
    }

    fn extract_tables_from_select(&self, select: &Query) -> Vec<String> {
        let mut tables = Vec::new();
        
        if let SetExpr::Select(select_stmt) = &*select.body {
            for table_with_joins in &select_stmt.from {
                if let Some(table_name) = self.extract_table_name(table_with_joins) {
                    tables.push(table_name);
                }
            }
        }
        
        tables
    }

    fn extract_table_name(&self, table_with_joins: &TableWithJoins) -> Option<String> {
        // Extract table name from TableWithJoins
        if let TableFactor::Table { name, .. } = &table_with_joins.relation {
            if !name.0.is_empty() {
                return Some(name.0.last().unwrap().value.clone());
            }
        }
        None
    }
}

impl Default for QueryRewriter {
    fn default() -> Self {
        // Create an empty in-memory database with tokio block_on
        // (This isn't ideal, but works for a default implementation)
        let runtime = Runtime::new().expect("Failed to create runtime");
        let db = runtime.block_on(async {
            Builder::new_local("file::memory:").build().await.expect("Failed to create in-memory database")
        });
        
        // Create a Policy Manager with the same database
        let db_arc = Arc::new(db);
        let policy_manager = PolicyManager::new(db_arc.clone());
        
        Self::new(db_arc, policy_manager)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsql::Builder;

    impl QueryRewriter {
        pub async fn new_for_test() -> Self {
            let db = Arc::new(
                Builder::new_local("file::memory:")
                    .build()
                    .await
                    .expect("Failed to create in-memory database")
            );
            
            // Create a Policy Manager that works with our database
            let policy_manager = PolicyManager::new(db.clone());
            
            Self::new(db, policy_manager)
        }
    }
} 