use sqlparser::ast::{self, Statement, TableFactor, Expr, ObjectName, Query, SetExpr, Select, SelectItem};
use anyhow::Result;
use crate::error::Error;

/// A visitor for SQL AST nodes
pub trait Visitor {
    /// Visit a table reference
    fn visit_table(&mut self, table: &TableFactor) -> Result<()>;
    
    /// Visit a statement (default implementation)
    fn visit_statement(&mut self, stmt: &Statement) -> Result<()> {
        match stmt {
            Statement::Query(query) => self.visit_query(query),
            _ => Ok(()),
        }
    }
    
    /// Visit a query (default implementation)
    fn visit_query(&mut self, query: &Query) -> Result<()> {
        match &*query.body {
            SetExpr::Select(select) => self.visit_select(select),
            _ => Ok(()),
        }
    }
    
    /// Visit a SELECT statement (default implementation)
    fn visit_select(&mut self, select: &Select) -> Result<()> {
        for table_with_joins in &select.from {
            self.visit_table(&table_with_joins.relation)?;
            
            // Visit joined tables
            for join in &table_with_joins.joins {
                self.visit_table(&join.relation)?;
            }
        }
        Ok(())
    }
}

/// Handles manipulation of SQL Abstract Syntax Trees
pub struct AstManipulator;

impl AstManipulator {
    /// Create a new AST manipulator
    pub fn new() -> Self {
        Self
    }

    /// Add a WHERE condition to a SELECT statement
    pub fn add_where_condition(&self, stmt: &mut Statement, table_name: &str, condition: Expr) -> Result<()> {
        match stmt {
            Statement::Query(query) => {
                self.add_where_to_query(query, table_name, condition)?;
                Ok(())
            },
            _ => Err(Error::RewritingError("Can only add WHERE conditions to SELECT statements".to_string()).into()),
        }
    }

    /// Add a WHERE condition to a Query
    fn add_where_to_query(&self, query: &mut Box<Query>, table_name: &str, condition: Expr) -> Result<()> {
        match &mut *query.body {
            SetExpr::Select(select) => {
                self.add_where_to_select(select, table_name, condition)?;
                Ok(())
            },
            _ => Err(Error::RewritingError("Only SELECT queries are supported for RLS".to_string()).into()),
        }
    }

    /// Add a WHERE condition to a Select statement
    fn add_where_to_select(&self, select: &mut Box<Select>, table_name: &str, condition: Expr) -> Result<()> {
        // Check if the table exists in the FROM clause
        let table_present = select.from.iter().any(|table_with_joins| {
            match &table_with_joins.relation {
                TableFactor::Table { name, .. } => self.object_name_matches(name, table_name),
                _ => false,
            }
        });

        if !table_present {
            return Ok(());  // Table not in this query, don't modify
        }

        // If WHERE already exists, AND it with the new condition
        if let Some(ref mut where_clause) = select.selection {
            *where_clause = Expr::BinaryOp {
                left: Box::new(where_clause.clone()),
                op: ast::BinaryOperator::And,
                right: Box::new(condition),
            };
        } else {
            // Otherwise, set the WHERE clause to the condition
            select.selection = Some(condition);
        }

        Ok(())
    }

    /// Check if an ObjectName matches a table name string
    fn object_name_matches(&self, name: &ObjectName, table_name: &str) -> bool {
        if name.0.len() == 1 {
            // For simple table names without schema
            name.0[0].value.eq_ignore_ascii_case(table_name)
        } else if name.0.len() == 2 {
            // For schema.table format
            name.0[1].value.eq_ignore_ascii_case(table_name)
        } else {
            false
        }
    }

    /// Parse a string expression into an Expr AST node
    pub fn parse_expr(&self, expr_str: &str) -> Result<Expr> {
        // This is a placeholder - in a real implementation you would 
        // use sqlparser to properly parse the expression string
        // Here we just create a simple identifier expression for demo purposes
        
        Ok(Expr::Identifier(ast::Ident::new(expr_str)))
    }

    /// Extract table names from a statement
    pub fn extract_table_names(&self, stmt: &Statement) -> Vec<String> {
        let mut extractor = TableNameExtractor::new();
        let _ = extractor.visit_statement(stmt);
        extractor.table_names
    }
}

/// A visitor that extracts table names from an AST
struct TableNameExtractor {
    table_names: Vec<String>,
}

impl TableNameExtractor {
    fn new() -> Self {
        Self {
            table_names: Vec::new(),
        }
    }
}

impl Visitor for TableNameExtractor {
    fn visit_table(&mut self, table: &TableFactor) -> Result<()> {
        if let TableFactor::Table { name, .. } = table {
            if !name.0.is_empty() {
                let table_name = name.0.last().unwrap().value.clone();
                self.table_names.push(table_name);
            }
        }
        Ok(())
    }
}

impl Default for AstManipulator {
    fn default() -> Self {
        Self::new()
    }
} 