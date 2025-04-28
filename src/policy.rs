use anyhow::Result;
use libsql::Database;
use crate::error::Error;
use crate::parser::RlsOperation;

/// A row-level security policy
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

    /// Check if this policy applies to a given operation
    pub fn applies_to(&self, operation: &RlsOperation) -> bool {
        match self.operation {
            RlsOperation::All => true,
            _ => self.operation == *operation,
        }
    }
}

/// Manages row-level security policies
pub struct PolicyManager {
    database: Database,
}

impl PolicyManager {
    /// Create a new policy manager
    pub fn new(database: Database) -> Self {
        Self { database }
    }

    /// Create a new policy
    pub async fn create_policy(&self, policy: &Policy) -> Result<()> {
        let conn = self.database.connect()?;
        
        // Check if the table has RLS enabled
        let row = conn.query_row(
            "SELECT enabled FROM _rls_tables WHERE table_name = ?",
            [&policy.table],
        ).await?;
        
        let enabled: bool = row.get(0)?;
        
        if !enabled {
            return Err(Error::PolicyError(format!(
                "Cannot create policy on table '{}' because RLS is not enabled",
                policy.table
            )).into());
        }
        
        // Check if a policy with the same name already exists
        let exists = conn.query_row(
            "SELECT COUNT(*) FROM _rls_policies WHERE policy_name = ? AND table_name = ?",
            [&policy.name, &policy.table],
        ).await?;
        
        let count: i64 = exists.get(0)?;
        
        if count > 0 {
            return Err(Error::PolicyError(format!(
                "Policy '{}' already exists on table '{}'",
                policy.name, policy.table
            )).into());
        }
        
        // Insert the policy
        let operation = match policy.operation {
            RlsOperation::Select => "SELECT",
            RlsOperation::Insert => "INSERT",
            RlsOperation::Update => "UPDATE",
            RlsOperation::Delete => "DELETE",
            RlsOperation::All => "ALL",
        };
        
        conn.execute(
            "INSERT INTO _rls_policies (policy_name, table_name, operation, using_expr, check_expr) 
             VALUES (?, ?, ?, ?, ?)",
            (
                &policy.name,
                &policy.table,
                operation,
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
            "SELECT COUNT(*) FROM _rls_policies WHERE policy_name = ? AND table_name = ?",
            [&name, &table],
        ).await?;
        
        let count: i64 = exists.get(0)?;
        
        if count == 0 {
            return Err(Error::PolicyError(format!(
                "Policy '{}' does not exist on table '{}'",
                name, table
            )).into());
        }
        
        // Delete the policy
        conn.execute(
            "DELETE FROM _rls_policies WHERE policy_name = ? AND table_name = ?",
            [&name, &table],
        ).await?;
        
        Ok(())
    }

    /// Enable or disable RLS on a table
    pub async fn set_rls_enabled(&self, table: &str, enabled: bool) -> Result<()> {
        let conn = self.database.connect()?;
        
        // Check if the table exists in the database
        let table_exists = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            [&table],
        ).await?;
        
        let count: i64 = table_exists.get(0)?;
        
        if count == 0 {
            return Err(Error::PolicyError(format!(
                "Table '{}' does not exist",
                table
            )).into());
        }
        
        // Check if the table is already in the RLS tables list
        let rls_exists = conn.query_row(
            "SELECT COUNT(*) FROM _rls_tables WHERE table_name = ?",
            [&table],
        ).await?;
        
        let rls_count: i64 = rls_exists.get(0)?;
        
        if rls_count == 0 {
            // Insert new entry
            conn.execute(
                "INSERT INTO _rls_tables (table_name, enabled) VALUES (?, ?)",
                [&table, &enabled],
            ).await?;
        } else {
            // Update existing entry
            conn.execute(
                "UPDATE _rls_tables SET enabled = ? WHERE table_name = ?",
                [&enabled, &table],
            ).await?;
        }
        
        Ok(())
    }

    /// Check if RLS is enabled for a table
    pub async fn is_rls_enabled(&self, table: &str) -> Result<bool> {
        let conn = self.database.connect()?;
        
        // Check if the table has RLS enabled
        let row = conn.query_row(
            "SELECT enabled FROM _rls_tables WHERE table_name = ?",
            [&table],
        ).await;
        
        match row {
            Ok(row) => {
                let enabled: bool = row.get(0)?;
                Ok(enabled)
            },
            Err(_) => {
                // If the table isn't in the RLS tables list, RLS is not enabled
                Ok(false)
            }
        }
    }

    /// Get all policies for a table and operation
    pub async fn get_policies(&self, table: &str, operation: &RlsOperation) -> Result<Vec<Policy>> {
        let conn = self.database.connect()?;
        
        // Map the operation to SQL string
        let operation_str = match operation {
            RlsOperation::Select => "SELECT",
            RlsOperation::Insert => "INSERT",
            RlsOperation::Update => "UPDATE",
            RlsOperation::Delete => "DELETE",
            RlsOperation::All => "ALL",
        };
        
        // Get policies that match the table and operation
        let rows = conn.query_all(
            "SELECT policy_name, table_name, operation, using_expr, check_expr 
             FROM _rls_policies 
             WHERE table_name = ? AND (operation = ? OR operation = 'ALL')",
            [&table, &operation_str],
        ).await?;
        
        let mut policies = Vec::new();
        
        for row in rows {
            let name: String = row.get(0)?;
            let table: String = row.get(1)?;
            let op: String = row.get(2)?;
            let using_expr: Option<String> = row.get(3)?;
            let check_expr: Option<String> = row.get(4)?;
            
            let operation = match op.as_str() {
                "SELECT" => RlsOperation::Select,
                "INSERT" => RlsOperation::Insert,
                "UPDATE" => RlsOperation::Update,
                "DELETE" => RlsOperation::Delete,
                "ALL" => RlsOperation::All,
                _ => RlsOperation::All, // Default to all
            };
            
            policies.push(Policy {
                name,
                table,
                operation,
                using_expr,
                check_expr,
            });
        }
        
        Ok(policies)
    }
} 