use crate::Result;
use libsql::{Connection, params};
use regex::Regex;
use lazy_static::lazy_static;

lazy_static! {
    // Basic regex pattern for CREATE POLICY statements
    static ref CREATE_POLICY_REGEX: Regex = Regex::new(
        r"(?i)CREATE\s+POLICY\s+(\w+)\s+ON\s+([\w\.]+)(?:\s+FOR\s+(\w+))?(?:\s+USING\s+\((.*?)\))?(?:\s+WITH\s+CHECK\s+\((.*?)\))?").unwrap();
}

/// Represents a row-level security policy
#[derive(Debug, Clone)]
pub struct Policy {
    pub name: String,
    pub schema_name: Option<String>,
    pub table_name: String,
    pub command: String, // SELECT, INSERT, UPDATE, DELETE, or ALL
    pub using_expr: Option<String>,
    pub check_expr: Option<String>,
}

/// Manages the creation, storage, and retrieval of RLS policies
pub struct PolicyManager {
    conn: Connection,
}

impl PolicyManager {
    /// Creates a new PolicyManager with the given libSQL connection
    pub async fn new(conn: Connection) -> Result<Self> {
        // Ensure the RLS policy table exists
        Self::init_policy_table(&conn).await?;
        Ok(Self { conn })
    }

    /// Initialize the policy table if it doesn't exist
    async fn init_policy_table(conn: &Connection) -> Result<()> {
        conn.execute(
            "CREATE TABLE IF NOT EXISTS _rls_policies (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                schema_name TEXT,
                table_name TEXT NOT NULL,
                command TEXT NOT NULL,
                using_expr TEXT,
                check_expr TEXT,
                UNIQUE(name, schema_name, table_name)
            )",
            params![],
        ).await?;
        Ok(())
    }

    /// Parse a CREATE POLICY statement and store it in the policy table
    pub async fn create_policy(&self, sql: &str) -> Result<Policy> {
        // Parse the policy from the SQL statement
        let policy = Self::parse_create_policy(sql)?;
        
        // Store the policy in the database
        self.store_policy(&policy).await?;
        
        Ok(policy)
    }
    
    /// Parse a CREATE POLICY statement using regular expressions
    fn parse_create_policy(sql: &str) -> Result<Policy> {
        // Use regex to extract policy details
        if let Some(captures) = CREATE_POLICY_REGEX.captures(sql) {
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
            
            Ok(Policy {
                name: policy_name,
                schema_name,
                table_name,
                command,
                using_expr,
                check_expr,
            })
        } else {
            Err(crate::Error::Policy("Invalid CREATE POLICY statement format".to_string()))
        }
    }
    
    /// Store a policy in the database
    async fn store_policy(&self, policy: &Policy) -> Result<()> {
        self.conn.execute(
            "INSERT INTO _rls_policies (name, schema_name, table_name, command, using_expr, check_expr)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                policy.name.clone(),
                policy.schema_name.clone(),
                policy.table_name.clone(),
                policy.command.clone(),
                policy.using_expr.clone(),
                policy.check_expr.clone(),
            ],
        ).await?;
        Ok(())
    }
    
    /// Get policies for a specific table
    pub async fn get_policies_for_table(&self, _schema_name: Option<&str>, _table_name: &str) -> Result<Vec<Policy>> {
        // Just for the prototype, return an empty Vec
        // This would normally query the database for matching policies
        Ok(Vec::new())
    }
} 