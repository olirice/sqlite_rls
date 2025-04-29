use crate::Result;
use libsql::{Connection, params, Rows};
use libsql::params::IntoParams;
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Basic regex pattern for CREATE POLICY statements
    // This captures:
    // 1. Policy name
    // 2. Table name (including schema if present)
    // 3. Optional command (SELECT, INSERT, etc.)
    // 4. Optional USING expression
    // 5. Optional WITH CHECK expression
    static ref CREATE_POLICY_REGEX: Regex = Regex::new(
        r"(?i)CREATE\s+POLICY\s+(\w+)\s+ON\s+([\w\.]+)(?:\s+FOR\s+(\w+))?(?:\s+USING\s+\(([^)]*)\))?(?:\s+WITH\s+CHECK\s+\(([^)]*)\))?").unwrap();
}

/// A wrapper around a libSQL connection that adds RLS functionality
/// 
/// This connection wrapper intercepts SQL statements and provides row-level security
/// capabilities by:
/// 
/// 1. Recognizing and processing CREATE POLICY statements
/// 2. Storing policy information in the _rls_policies table
/// 3. (Future) Rewriting SELECT statements to apply RLS policies
pub struct RlsConnection {
    conn: Connection,
}

impl RlsConnection {
    /// Create a new RLS connection wrapper
    /// 
    /// # Arguments
    /// 
    /// * `conn` - The libSQL connection to wrap
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
    
    /// Execute a SQL statement with RLS processing
    /// 
    /// This method intercepts CREATE POLICY statements and processes them
    /// accordingly. For other statements, it passes them through to the
    /// underlying connection.
    /// 
    /// # Arguments
    /// 
    /// * `sql` - The SQL statement to execute
    /// * `params_values` - The parameters to bind to the statement
    pub async fn execute<P>(&self, sql: &str, params_values: P) -> Result<u64> 
    where
        P: IntoParams,
    {
        // Check if it's a CREATE POLICY statement
        if let Some(captures) = CREATE_POLICY_REGEX.captures(sql) {
            // Parse the policy
            let policy_name = captures.get(1).map_or("", |m| m.as_str()).to_string();
            let table_ref = captures.get(2).map_or("", |m| m.as_str());
            let command = captures.get(3).map_or("ALL", |m| m.as_str()).to_uppercase();
            let using_expr = captures.get(4).map(|m| m.as_str().to_string());
            let check_expr = captures.get(5).map(|m| m.as_str().to_string());
            
            // Parse table reference (with optional schema)
            let (schema_name, table_name) = if table_ref.contains('.') {
                let parts: Vec<&str> = table_ref.split('.').collect();
                (Some(parts[0].to_string()), parts[1].to_string())
            } else {
                (None, table_ref.to_string())
            };
            
            // Store the policy in the database
            self.conn.execute(
                "INSERT INTO _rls_policies (name, schema_name, table_name, command, using_expr, check_expr)
                 VALUES (?, ?, ?, ?, ?, ?)",
                params![
                    policy_name,
                    schema_name,
                    table_name,
                    command,
                    using_expr,
                    check_expr,
                ],
            ).await.map_err(Into::into)
        } else {
            // Otherwise, just execute the SQL as is
            // In a future implementation, this would rewrite SELECT statements to apply RLS
            self.conn.execute(sql, params_values).await.map_err(Into::into)
        }
    }
    
    /// Execute a query and return the rows
    /// 
    /// Currently, this just passes the query through to the underlying connection.
    /// In a full implementation, this would rewrite SELECT statements to enforce RLS.
    /// 
    /// # Arguments
    /// 
    /// * `sql` - The SQL query to execute
    /// * `params_values` - The parameters to bind to the query
    pub async fn query<P>(&self, sql: &str, params_values: P) -> Result<Rows>
    where
        P: IntoParams,
    {
        // For now, just pass through to the underlying connection
        // In a full implementation, this would rewrite SELECT statements to enforce RLS
        self.conn.query(sql, params_values).await.map_err(Into::into)
    }
} 