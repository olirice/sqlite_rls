use anyhow::{anyhow, Result};
use crate::parser::RlsOperation;
use crate::compat::{ConnectionExt, IntoParams};
use libsql::Database;
use std::sync::Arc;

/// Represents database operations that a policy can apply to
#[derive(Debug, Clone, PartialEq)]
pub enum Operation {
    Select,
    Insert,
    Update,
    Delete,
    All,
}

impl From<RlsOperation> for Operation {
    fn from(op: RlsOperation) -> Self {
        match op {
            RlsOperation::Select => Operation::Select,
            RlsOperation::Insert => Operation::Insert,
            RlsOperation::Update => Operation::Update,
            RlsOperation::Delete => Operation::Delete,
            RlsOperation::All => Operation::All,
        }
    }
}

/// Represents a Row Level Security policy
#[derive(Debug, Clone)]
pub struct Policy {
    /// The name of the policy
    pub name: String,
    /// The table the policy applies to
    pub table: String,
    /// The operation the policy applies to
    pub operation: RlsOperation,
    /// The USING expression (applied to existing rows)
    pub using_expr: Option<String>,
    /// The CHECK expression (applied to new/modified rows)
    pub check_expr: Option<String>,
}

impl Policy {
    /// Create a new policy
    pub fn new(
        name: impl Into<String>,
        table: impl Into<String>,
        operation: RlsOperation,
        using_expr: Option<String>,
        check_expr: Option<String>,
    ) -> Self {
        Self {
            name: name.into(),
            table: table.into(),
            operation,
            using_expr,
            check_expr,
        }
    }

    /// Get the policy name
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the table name
    pub fn table(&self) -> &str {
        &self.table
    }

    /// Get the operation
    pub fn operation(&self) -> &RlsOperation {
        &self.operation
    }

    /// Get the USING expression
    pub fn using_expr(&self) -> &Option<String> {
        &self.using_expr
    }

    /// Get the CHECK expression
    pub fn check_expr(&self) -> &Option<String> {
        &self.check_expr
    }

    /// Check if this policy applies to a given operation
    pub fn applies_to(&self, operation: &RlsOperation) -> bool {
        match self.operation {
            RlsOperation::All => true,
            _ => self.operation == *operation,
        }
    }
}

/// Manages RLS policies in the database
pub struct PolicyManager {
    database: Arc<Database>,
}

impl PolicyManager {
    /// Create a new policy manager
    pub fn new(database: Arc<Database>) -> Self {
        Self { database }
    }

    /// Get all policies for a table and operation
    pub async fn get_policies(&self, table: &str, operation: &RlsOperation) -> Result<Vec<Policy>> {
        let conn = self.database.connect()?;
        let op_str = operation.to_string();

        // Get all policies for this table and operation
        let rows = conn.query_all(
            "SELECT policy_name, table_name, operation, using_expr, check_expr
             FROM _rls_policies
             WHERE table_name = ? AND operation = ?",
            (table, op_str),
        ).await?;

        let mut policies = Vec::new();
        for row in rows {
            let policy = Policy {
                name: row.get::<String>(0)?,
                table: row.get::<String>(1)?,
                operation: RlsOperation::from_str(&row.get::<String>(2)?)?,
                using_expr: row.get::<Option<String>>(3)?,
                check_expr: row.get::<Option<String>>(4)?,
            };
            policies.push(policy);
        }

        Ok(policies)
    }

    /// Check if a policy exists
    pub async fn policy_exists(&self, name: &str, table: &str) -> Result<bool> {
        let conn = self.database.connect()?;
        let row = conn.query_row(
            "SELECT 1 FROM _rls_policies WHERE policy_name = ? AND table_name = ?",
            (name, table),
        ).await?;

        Ok(row.is_some())
    }

    /// Create a new policy
    pub async fn create_policy(&self, policy: &Policy) -> Result<()> {
        let conn = self.database.connect()?;
        
        // Check if the policy already exists
        let exists = conn.query_row(
            "SELECT 1 FROM _rls_policies WHERE policy_name = ? AND table_name = ?",
            (policy.name.as_str(), policy.table.as_str()),
        ).await?;

        if exists.is_some() {
            return Err(anyhow!("Policy {} already exists on table {}", policy.name, policy.table));
        }

        // Check if the table exists
        let table_exists = self.table_exists(&policy.table).await?;
        if !table_exists {
            return Err(anyhow!("Table {} does not exist", policy.table));
        }

        // Insert the policy
        conn.execute(
            "INSERT INTO _rls_policies (policy_name, table_name, operation, using_expr, check_expr)
             VALUES (?, ?, ?, ?, ?)",
            (
                policy.name.as_str(),
                policy.table.as_str(),
                policy.operation.to_string(),
                policy.using_expr.as_deref(),
                policy.check_expr.as_deref(),
            ),
        ).await?;

        Ok(())
    }

    /// Drop a policy
    pub async fn drop_policy(&self, name: &str, table: &str) -> Result<()> {
        let conn = self.database.connect()?;
        
        // Check if the policy exists
        let exists = conn.query_row(
            "SELECT 1 FROM _rls_policies WHERE policy_name = ? AND table_name = ?",
            (name, table),
        ).await?;

        if exists.is_none() {
            return Err(anyhow!("Policy {} does not exist on table {}", name, table));
        }

        // Delete the policy
        conn.execute(
            "DELETE FROM _rls_policies WHERE policy_name = ? AND table_name = ?",
            (name, table),
        ).await?;

        Ok(())
    }

    /// Check if a table exists
    pub async fn table_exists(&self, table: &str) -> Result<bool> {
        let conn = self.database.connect()?;
        let table_exists = conn.query_row(
            "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
            table,
        ).await?;

        Ok(table_exists.is_some())
    }

    /// Check if RLS is enabled for a table
    pub async fn is_rls_enabled(&self, table: &str) -> Result<bool> {
        let conn = self.database.connect()?;
        
        // Check if the table is in the RLS tables list
        let rls_exists = conn.query_row(
            "SELECT enabled FROM _rls_tables WHERE table_name = ?",
            table,
        ).await?;

        match rls_exists {
            Some(row) => Ok(row.get::<i64>(0)? != 0),
            None => Ok(false),
        }
    }

    /// Enable or disable RLS for a table
    pub async fn set_rls_enabled(&self, table: &str, enabled: bool) -> Result<()> {
        let conn = self.database.connect()?;
        
        // Check if the table exists
        let table_exists = self.table_exists(table).await?;
        if !table_exists {
            return Err(anyhow!("Table {} does not exist", table));
        }

        // Check if the table is already in the RLS tables list
        let row = conn.query_row(
            "SELECT enabled FROM _rls_tables WHERE table_name = ?",
            table,
        ).await?;

        let enabled_val = if enabled { 1 } else { 0 };

        if let Some(_) = row {
            // Update existing row
            conn.execute(
                "UPDATE _rls_tables SET enabled = ? WHERE table_name = ?",
                (enabled_val, table),
            ).await?;
        } else {
            // Insert new row
            conn.execute(
                "INSERT INTO _rls_tables (table_name, enabled) VALUES (?, ?)",
                (table, enabled_val),
            ).await?;
        }

        Ok(())
    }

    /// Get a policy by name and table
    pub async fn get_policy(&self, name: &str, table: &str) -> Result<Option<Policy>> {
        let conn = self.database.connect()?;
        
        let row = conn.query_row(
            "SELECT policy_name, table_name, operation, using_expr, check_expr
             FROM _rls_policies
             WHERE policy_name = ? AND table_name = ?",
            (name, table),
        ).await?;

        match row {
            Some(row) => {
                let policy = Policy {
                    name: row.get::<String>(0)?,
                    table: row.get::<String>(1)?,
                    operation: RlsOperation::from_str(&row.get::<String>(2)?)?,
                    using_expr: row.get::<Option<String>>(3)?,
                    check_expr: row.get::<Option<String>>(4)?,
                };
                Ok(Some(policy))
            },
            None => Ok(None),
        }
    }

    /// Get all policies for a table
    pub async fn get_table_policies(&self, table: &str) -> Result<Vec<Policy>> {
        let conn = self.database.connect()?;
        
        let rows = conn.query_all(
            "SELECT policy_name, table_name, operation, using_expr, check_expr
             FROM _rls_policies
             WHERE table_name = ?",
            table,
        ).await?;

        let mut policies = Vec::new();
        for row in rows {
            let policy = Policy {
                name: row.get::<String>(0)?,
                table: row.get::<String>(1)?,
                operation: RlsOperation::from_str(&row.get::<String>(2)?)?,
                using_expr: row.get::<Option<String>>(3)?,
                check_expr: row.get::<Option<String>>(4)?,
            };
            policies.push(policy);
        }

        Ok(policies)
    }

    /// Get all tables with RLS enabled
    pub async fn get_rls_tables(&self) -> Result<Vec<String>> {
        let conn = self.database.connect()?;
        
        let rows = conn.query_all(
            "SELECT table_name FROM _rls_tables WHERE enabled = 1",
            (),
        ).await?;

        let mut tables = Vec::new();
        for row in rows {
            tables.push(row.get::<String>(0)?);
        }

        Ok(tables)
    }
} 