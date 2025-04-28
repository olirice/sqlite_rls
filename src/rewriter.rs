use anyhow::Result;
use sqlparser::ast::{self, Statement, TableFactor};
use crate::error::Error;
use crate::ast::AstManipulator;
use crate::policy::{Policy, PolicyManager};
use crate::parser::RlsOperation;
use libsql::Database;

/// Handles rewriting SQL statements to apply RLS policies
pub struct Rewriter {
    ast_manipulator: AstManipulator,
    policy_manager: Option<PolicyManager>,
}

impl Rewriter {
    /// Create a new rewriter
    pub fn new() -> Self {
        Self {
            ast_manipulator: AstManipulator::new(),
            policy_manager: None,
        }
    }

    /// Set the policy manager
    pub fn with_policy_manager(mut self, database: Database) -> Self {
        self.policy_manager = Some(PolicyManager::new(database));
        self
    }

    /// Rewrite a statement to apply RLS
    pub async fn rewrite(&self, mut stmt: Statement) -> Result<Statement> {
        match &stmt {
            Statement::Query(_) => {
                self.rewrite_select(&mut stmt).await?;
            },
            Statement::Insert { .. } => {
                self.rewrite_insert(&mut stmt).await?;
            },
            Statement::Update { .. } => {
                self.rewrite_update(&mut stmt).await?;
            },
            Statement::Delete { .. } => {
                self.rewrite_delete(&mut stmt).await?;
            },
            _ => {
                // Other statements don't need RLS
            },
        }
        
        Ok(stmt)
    }
    
    /// Rewrite a SELECT statement with RLS policies
    async fn rewrite_select(&self, stmt: &mut Statement) -> Result<()> {
        // Extract table names from the statement
        let table_names = self.extract_table_names(stmt)?;
        
        if let Some(policy_manager) = &self.policy_manager {
            // For each table, apply any RLS policies
            for table_name in table_names {
                // Check if RLS is enabled for this table
                let rls_enabled = policy_manager.is_rls_enabled(&table_name).await?;
                
                if !rls_enabled {
                    continue;
                }
                
                // Get policies for this table and operation
                let policies = policy_manager.get_policies(&table_name, &RlsOperation::Select).await?;
                
                if policies.is_empty() {
                    // If no policies, deny all access
                    let deny_condition = ast::Expr::Value(ast::Value::Boolean(false));
                    self.ast_manipulator.add_where_condition(stmt, &table_name, deny_condition)?;
                } else {
                    // Combine all policy conditions with OR
                    let mut combined_condition = None;
                    
                    for policy in policies {
                        if let Some(using_expr) = &policy.using_expr {
                            let condition = self.ast_manipulator.parse_expr(using_expr)?;
                            
                            if let Some(existing) = combined_condition {
                                combined_condition = Some(ast::Expr::BinaryOp {
                                    left: Box::new(existing),
                                    op: ast::BinaryOperator::Or,
                                    right: Box::new(condition),
                                });
                            } else {
                                combined_condition = Some(condition);
                            }
                        }
                    }
                    
                    // Apply the combined condition
                    if let Some(condition) = combined_condition {
                        self.ast_manipulator.add_where_condition(stmt, &table_name, condition)?;
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Rewrite an INSERT statement with RLS policies
    async fn rewrite_insert(&self, stmt: &mut Statement) -> Result<()> {
        // For simplicity, we'll just stub these out for now
        // In a real implementation, you'd apply CHECK expressions to INSERT statements
        Ok(())
    }
    
    /// Rewrite an UPDATE statement with RLS policies
    async fn rewrite_update(&self, stmt: &mut Statement) -> Result<()> {
        // For simplicity, we'll just stub these out for now
        // In a real implementation, you'd apply both USING and CHECK expressions
        Ok(())
    }
    
    /// Rewrite a DELETE statement with RLS policies
    async fn rewrite_delete(&self, stmt: &mut Statement) -> Result<()> {
        // For simplicity, we'll just stub these out for now
        // In a real implementation, you'd apply USING expressions to DELETE statements
        Ok(())
    }
    
    /// Extract table names from a statement
    fn extract_table_names(&self, stmt: &Statement) -> Result<Vec<String>> {
        let mut table_names = Vec::new();
        
        match stmt {
            Statement::Query(query) => {
                // Extract tables from query
                match &query.body {
                    ast::SetExpr::Select(select) => {
                        for table_with_joins in &select.from {
                            if let TableFactor::Table { name, .. } = &table_with_joins.relation {
                                if name.0.len() > 0 {
                                    // Get the last part of the name (e.g., "table" from "schema.table")
                                    let table_name = name.0.last().unwrap().value.clone();
                                    table_names.push(table_name);
                                }
                            }
                        }
                    },
                    _ => {},
                }
            },
            Statement::Insert { table_name, .. } => {
                if !table_name.0.is_empty() {
                    table_names.push(table_name.0.last().unwrap().value.clone());
                }
            },
            Statement::Update { table, .. } => {
                if let TableFactor::Table { name, .. } = table {
                    if !name.0.is_empty() {
                        table_names.push(name.0.last().unwrap().value.clone());
                    }
                }
            },
            Statement::Delete { table_name, .. } => {
                if !table_name.0.is_empty() {
                    table_names.push(table_name.0.last().unwrap().value.clone());
                }
            },
            _ => {
                // Other statements don't have tables to protect
            },
        }
        
        Ok(table_names)
    }
}

impl Default for Rewriter {
    fn default() -> Self {
        Self::new()
    }
} 