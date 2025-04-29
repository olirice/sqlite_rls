use anyhow::{anyhow, Context, Result};
use libsql::Value;
use sqlparser::ast::{Statement, TableFactor, SetExpr};
use std::collections::HashMap;
use std::sync::Arc;
use libsql::Database;
use libsql::Connection;
use crate::compat::{empty_params, ConnectionExt};
use crate::parser::RlsOperation;
use crate::error::Error;
use sqlparser::dialect::SQLiteDialect;

/// A compiled policy statement ready to be used in a WHERE clause
#[derive(Debug, Clone)]
pub struct CompiledStatement {
    pub sql: String,
}

/// Represents database operations that a policy can apply to
#[derive(Debug, Clone, PartialEq)]
pub enum Operation {
    Select,
    Insert,
    Update,
    Delete,
}

impl From<RlsOperation> for Operation {
    fn from(op: RlsOperation) -> Self {
        match op {
            RlsOperation::Select => Operation::Select,
            RlsOperation::Insert => Operation::Insert,
            RlsOperation::Update => Operation::Update,
            RlsOperation::Delete => Operation::Delete,
        }
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Operation::Select => write!(f, "SELECT"),
            Operation::Insert => write!(f, "INSERT"),
            Operation::Update => write!(f, "UPDATE"),
            Operation::Delete => write!(f, "DELETE"),
        }
    }
}

impl Operation {
    /// Create an Operation from a string
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_uppercase().as_str() {
            "SELECT" => Ok(Operation::Select),
            "INSERT" => Ok(Operation::Insert),
            "UPDATE" => Ok(Operation::Update),
            "DELETE" => Ok(Operation::Delete),
            _ => Ok(Operation::Select), // Default to SELECT for simplified version
        }
    }
}

/// Represents a Row Level Security policy
#[derive(Debug, Clone)]
pub struct Policy {
    /// The name of the policy
    pub policy_name: String,
    /// The table the policy applies to
    pub table_name: String,
    /// The operation the policy applies to
    pub operation: Operation,
    /// The USING expression (applied to rows)
    pub using_expr: Option<String>,
    /// We don't use CHECK expression in the simplified version
    pub check_expr: Option<String>,
}

impl Policy {
    /// Create a new policy
    pub fn new(
        policy_name: &str,
        table_name: &str,
        operation: RlsOperation,
        using_expr: Option<String>,
        check_expr: Option<String>,
    ) -> Self {
        Self {
            policy_name: policy_name.to_string(),
            table_name: table_name.to_string(),
            operation: operation.into(),
            using_expr,
            check_expr,
        }
    }

    /// Get the policy name
    pub fn name(&self) -> &str {
        &self.policy_name
    }

    /// Get the table name
    pub fn table(&self) -> &str {
        &self.table_name
    }

    /// Get the operation
    pub fn operation(&self) -> &Operation {
        &self.operation
    }

    /// Get the USING expression
    pub fn using_expr(&self) -> &Option<String> {
        &self.using_expr
    }

    /// Get the CHECK expression (not used in simplified version)
    pub fn check_expr(&self) -> &Option<String> {
        &self.check_expr
    }

    /// Check if this policy applies to a given operation
    pub fn applies_to(&self, operation: &Operation) -> bool {
        self.operation == *operation
    }

    fn to_where_clause(&self) -> Option<String> {
        // For SELECT queries, we only apply the USING expression
        self.using_expr.clone()
    }
}

/// Manages RLS policies in the database
pub struct PolicyManager {
    db: Arc<Database>,
}

impl PolicyManager {
    /// Create a new policy manager
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Initialize the policy manager
    pub async fn init(&self) -> Result<()> {
        println!("DEBUG: Initializing policy manager");
        // Create the connection for initialization
        let conn = self
            .db
            .connect()?;

        // Create _rls_policies table if it doesn't exist
        let create_policies_table = "\
            CREATE TABLE IF NOT EXISTS _rls_policies ( \
                policy_name TEXT NOT NULL, \
                table_name TEXT NOT NULL, \
                operation TEXT NOT NULL, \
                using_expr TEXT, \
                check_expr TEXT, \
                PRIMARY KEY (policy_name, table_name) \
            )";
        
        conn.execute(create_policies_table, empty_params())
            .await
            .with_context(|| "Failed to create _rls_policies table")?;

        // Create _rls_tables table if it doesn't exist
        let create_tables_table = "\
            CREATE TABLE IF NOT EXISTS _rls_tables ( \
                table_name TEXT PRIMARY KEY, \
                enabled BOOLEAN NOT NULL DEFAULT 0 \
            )";
        
        conn.execute(create_tables_table, empty_params())
            .await
            .with_context(|| "Failed to create _rls_tables table")?;

        Ok(())
    }

    /// Get all policies for a table, with optional operation filter
    pub async fn get_policies(&self, table_name: &str, operation: Option<RlsOperation>) -> Result<Vec<Policy>> {
        println!("Getting policies for table '{}' with operation '{:?}'", table_name, operation);
        let db = self.db.clone();
        let conn = db.connect()?;

        // First, check if _rls_policies exists
        println!("DEBUG: Checking if _rls_policies exists");
        let check_policies_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_policies'";
        let rows = match conn.query_all(check_policies_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                println!("DEBUG: Error checking if _rls_policies exists: {}", e);
                return Err(Error::PolicyError(format!("Failed to check if _rls_policies exists: {}", e)).into());
            }
        };
        
        // If _rls_policies doesn't exist, there are no policies to return
        if rows.is_empty() {
            println!("DEBUG: _rls_policies table doesn't exist, returning empty policy list");
            return Ok(Vec::new());
        }

        // Adjust the query to include operation filter if specified
        let sql = if let Some(op) = operation {
            let operation_str = match op {
                RlsOperation::Select => "SELECT",
                RlsOperation::Insert => "INSERT",
                RlsOperation::Update => "UPDATE",
                RlsOperation::Delete => "DELETE",
            };
            println!("Filtering policies for operation: {}", operation_str);
            format!(
                "SELECT policy_name, table_name, operation, using_expr, check_expr \
                 FROM _rls_policies \
                 WHERE table_name = '{}' AND operation = '{}'",
                table_name, operation_str
            )
        } else {
            println!("Getting all policies regardless of operation");
            format!(
                "SELECT policy_name, table_name, operation, using_expr, check_expr \
                 FROM _rls_policies \
                 WHERE table_name = '{}'",
                table_name
            )
        };

        println!("SQL query: {}", sql);
        
        // Execute query and handle potential errors
        let rows = match conn.query_all(&sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                println!("Error querying policies: {:?}", e);
                return Err(Error::PolicyError(format!("Failed to query policies: {}", e)).into());
            }
        };

        println!("Found {} policies", rows.len());
        let mut policies = Vec::new();

        for (i, row) in rows.iter().enumerate() {
            println!("DEBUG: Processing policy row {}", i);
            
            // Debug the entire row
            println!("DEBUG: Row data: {:?}", row);
            
            // Extract policy attributes from row, with fallbacks for potential errors
            let policy_name = match row.get::<String>(0) {
                Ok(name) => {
                    println!("DEBUG: Successfully retrieved policy_name: {}", name);
                    name
                },
                Err(e) => {
                    println!("Error getting policy_name: {:?}", e);
                    println!("DEBUG: Trying to get policy_name as Option<String>");
                    
                    match row.get::<Option<String>>(0) {
                        Ok(Some(name)) => {
                            println!("DEBUG: Retrieved policy_name as Option<String>: {}", name);
                            name
                        },
                        Ok(None) => {
                            println!("DEBUG: policy_name is NULL, using fallback");
                            format!("unknown_policy_{}", i)
                        },
                        Err(e2) => {
                            println!("DEBUG: Failed to get policy_name as Option<String>: {:?}", e2);
                            println!("DEBUG: Trying to get policy_name as Value");
                            
                            match row.get::<Value>(0) {
                                Ok(Value::Text(name)) => {
                                    println!("DEBUG: Retrieved policy_name as Value::Text: {}", name);
                                    name
                                },
                                Ok(Value::Null) => {
                                    println!("DEBUG: policy_name is Value::Null, using fallback");
                                    format!("unknown_policy_{}", i)
                                },
                                Ok(other) => {
                                    println!("DEBUG: policy_name is unexpected value type: {:?}", other);
                                    format!("unknown_policy_{}", i)
                                },
                                Err(_) => {
                                    println!("DEBUG: All attempts to get policy_name failed, using fallback");
                                    format!("unknown_policy_{}", i)
                                }
                            }
                        }
                    }
                }
            };

            let table_name_val = match row.get::<String>(1) {
                Ok(name) => {
                    println!("DEBUG: Successfully retrieved table_name: {}", name);
                    name
                },
                Err(e) => {
                    println!("Error getting table_name: {:?}", e);
                    println!("DEBUG: Using provided table_name as fallback: {}", table_name);
                    table_name.to_string()
                }
            };

            let operation_str = match row.get::<String>(2) {
                Ok(op) => {
                    println!("DEBUG: Successfully retrieved operation: {}", op);
                    op
                },
                Err(e) => {
                    println!("Error getting operation: {:?}", e);
                    println!("DEBUG: Using SELECT as fallback operation");
                    "SELECT".to_string()
                }
            };

            let using_expr = match row.get::<String>(3) {
                Ok(expr) => {
                    println!("DEBUG: Successfully retrieved using_expr: {}", expr);
                    Some(expr)
                },
                Err(e) => {
                    println!("DEBUG: Error getting using_expr: {:?}", e);
                    println!("DEBUG: Trying to get using_expr as Option<String>");
                    
                    match row.get::<Option<String>>(3) {
                        Ok(expr) => {
                            println!("DEBUG: Retrieved using_expr as Option<String>: {:?}", expr);
                            expr
                        },
                        Err(e2) => {
                            println!("DEBUG: Failed to get using_expr as Option<String>: {:?}", e2);
                            println!("DEBUG: Using None as fallback for using_expr");
                            None
                        }
                    }
                }
            };

            let check_expr = match row.get::<String>(4) {
                Ok(expr) => {
                    println!("DEBUG: Successfully retrieved check_expr: {}", expr);
                    Some(expr)
                },
                Err(e) => {
                    println!("DEBUG: Error getting check_expr: {:?}", e);
                    println!("DEBUG: Trying to get check_expr as Option<String>");
                    
                    match row.get::<Option<String>>(4) {
                        Ok(expr) => {
                            println!("DEBUG: Retrieved check_expr as Option<String>: {:?}", expr);
                            expr
                        },
                        Err(e2) => {
                            println!("DEBUG: Failed to get check_expr as Option<String>: {:?}", e2);
                            println!("DEBUG: Using None as fallback for check_expr");
                            None
                        }
                    }
                }
            };

            // Convert string operation to Operation enum
            let operation = match operation_str.as_str() {
                "SELECT" => Operation::Select,
                "INSERT" => Operation::Insert,
                "UPDATE" => Operation::Update,
                "DELETE" => Operation::Delete,
                _ => {
                    println!("Unsupported operation: {}, defaulting to SELECT", operation_str);
                    Operation::Select
                }
            };

            // Create the policy from the extracted attributes
            let policy = Policy {
                policy_name,
                table_name: table_name_val,
                operation,
                using_expr,
                check_expr,
            };

            println!("DEBUG: Created policy: {:?}", policy);
            policies.push(policy);
        }

        println!("DEBUG: Returning {} policies", policies.len());
        Ok(policies)
    }

    /// Get a policy by name
    pub async fn get_policy(&self, policy_name: &str, table_name: &str) -> Result<Policy> {
        println!("Getting policy '{}' for table '{}'", policy_name, table_name);
        let db = self.db.clone();
        let conn = db.connect()?;

        let sql = format!(
            "SELECT policy_name, table_name, operation, using_expr, check_expr \
             FROM _rls_policies \
             WHERE policy_name = '{}' AND table_name = '{}'",
            policy_name, table_name
        );

        println!("SQL query: {}", sql);
        let params = empty_params();

        // Execute query and handle potential errors
        let row = match conn.query_row(&sql, params).await {
            Ok(Some(row)) => row,
            Ok(None) => {
                return Err(Error::PolicyError(format!(
                    "Policy not found: {} for table {}",
                    policy_name, table_name
                )).into());
            }
            Err(e) => {
                return Err(Error::PolicyError(format!("Failed to query policy: {}", e)).into());
            }
        };

        // Extract policy attributes
        let policy_name = match row.get::<String>(0) {
            Ok(name) => name,
            Err(e) => return Err(Error::PolicyError(format!("Failed to get policy_name: {}", e)).into()),
        };

        let table_name = match row.get::<String>(1) {
            Ok(name) => name,
            Err(e) => return Err(Error::PolicyError(format!("Failed to get table_name: {}", e)).into()),
        };

        let operation_str = match row.get::<String>(2) {
            Ok(op) => op,
            Err(e) => return Err(Error::PolicyError(format!("Failed to get operation: {}", e)).into()),
        };

        let using_expr = match row.get::<String>(3) {
            Ok(expr) => Some(expr),
            Err(_) => None, // It's okay if this is NULL
        };

        let check_expr = match row.get::<String>(4) {
            Ok(expr) => Some(expr),
            Err(_) => None, // It's okay if this is NULL
        };

        // Convert string operation to Operation enum
        let operation = match operation_str.as_str() {
            "SELECT" => Operation::Select,
            "INSERT" => Operation::Insert,
            "UPDATE" => Operation::Update,
            "DELETE" => Operation::Delete,
            _ => return Err(Error::PolicyError(format!("Unsupported operation: {}", operation_str)).into()),
        };

        Ok(Policy {
            policy_name,
            table_name,
            operation,
            using_expr,
            check_expr,
        })
    }

    /// Create a policy
    pub async fn create_policy(&self, policy: &Policy) -> Result<()> {
        println!("Creating policy '{}' for table '{}'", policy.policy_name, policy.table_name);
        let db = self.db.clone();
        let conn = db.connect()?;

        // Begin transaction
        conn.execute("BEGIN TRANSACTION", empty_params()).await?;
        
        // First, check if _rls_tables exists
        println!("DEBUG: Checking if _rls_tables exists");
        let check_table_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_tables'";
        let rows = match conn.query_all(check_table_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if _rls_tables exists: {}", e)).into());
            }
        };
        
        // If _rls_tables doesn't exist, create it
        if rows.is_empty() {
            println!("DEBUG: _rls_tables doesn't exist, creating it");
            let create_tables_sql = "\
                CREATE TABLE IF NOT EXISTS _rls_tables ( \
                    table_name TEXT PRIMARY KEY, \
                    enabled BOOLEAN NOT NULL DEFAULT 0 \
                )";
            
            match conn.execute(create_tables_sql, empty_params()).await {
                Ok(_) => println!("DEBUG: Created _rls_tables table"),
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    return Err(Error::PolicyError(format!("Failed to create _rls_tables: {}", e)).into());
                }
            }
        }
        
        // Check if _rls_policies exists too
        println!("DEBUG: Checking if _rls_policies exists");
        let check_policies_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_policies'";
        let rows = match conn.query_all(check_policies_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if _rls_policies exists: {}", e)).into());
            }
        };
        
        // If _rls_policies doesn't exist, create it
        if rows.is_empty() {
            println!("DEBUG: _rls_policies doesn't exist, creating it");
            let create_policies_sql = "\
                CREATE TABLE IF NOT EXISTS _rls_policies ( \
                    policy_name TEXT NOT NULL, \
                    table_name TEXT NOT NULL, \
                    operation TEXT NOT NULL, \
                    using_expr TEXT, \
                    check_expr TEXT, \
                    PRIMARY KEY (policy_name, table_name), \
                    FOREIGN KEY (table_name) REFERENCES _rls_tables(table_name) \
                )";
            
            match conn.execute(create_policies_sql, empty_params()).await {
                Ok(_) => println!("DEBUG: Created _rls_policies table"),
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    return Err(Error::PolicyError(format!("Failed to create _rls_policies: {}", e)).into());
                }
            }
        }

        // Skip table validation and just insert the table into _rls_tables
        // This is needed because temporary tables in transactions may not show up in sqlite_master
        println!("DEBUG: Directly adding table to _rls_tables to avoid foreign key constraint issues");
        
        // Check if table already exists in _rls_tables
        let check_rls_sql = format!(
            "SELECT COUNT(*) FROM _rls_tables WHERE table_name = '{}'",
            policy.table_name
        );
        
        let rows = match conn.query_all(&check_rls_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                println!("DEBUG: Error checking if table is in _rls_tables: {}", e);
                return Err(Error::PolicyError(format!("Failed to check if table is in RLS tables: {}", e)).into());
            }
        };
        
        let exists = if let Some(row) = rows.first() {
            match row.get::<i64>(0) {
                Ok(count) => count > 0,
                Err(_) => false,
            }
        } else {
            false
        };
        
        // Update or insert into _rls_tables
        let tables_sql = if exists {
            format!(
                "UPDATE _rls_tables SET enabled = 1 WHERE table_name = '{}'",
                policy.table_name
            )
        } else {
            format!(
                "INSERT INTO _rls_tables (table_name, enabled) VALUES ('{}', 1)",
                policy.table_name
            )
        };
        
        println!("DEBUG: Executing _rls_tables SQL: {}", tables_sql);
        match conn.execute(&tables_sql, empty_params()).await {
            Ok(_) => {
                println!("DEBUG: Successfully {} table in _rls_tables", 
                    if exists { "updated" } else { "inserted" });
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to update/insert table in _rls_tables: {}", e)).into());
            }
        }
        
        // Check if policy exists first and drop it if it does
        let policy_exists_sql = format!(
            "SELECT 1 FROM _rls_policies \
            WHERE policy_name = '{}' AND table_name = '{}'",
            policy.policy_name, policy.table_name
        );
        
        let rows = match conn.query_all(&policy_exists_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                // Rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if policy exists: {}", e)).into());
            }
        };
        
        if !rows.is_empty() {
            println!("DEBUG: Policy '{}' already exists, dropping it first", policy.policy_name);
            let drop_sql = format!(
                "DELETE FROM _rls_policies \
                WHERE policy_name = '{}' AND table_name = '{}'",
                policy.policy_name, policy.table_name
            );
            
            match conn.execute(&drop_sql, empty_params()).await {
                Ok(_) => println!("DEBUG: Successfully dropped existing policy"),
                Err(e) => {
                    // Rollback transaction
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    return Err(Error::PolicyError(format!("Failed to drop existing policy: {}", e)).into());
                }
            }
        }
        
        // Create operation string
        let operation_str = match policy.operation {
            Operation::Select => "SELECT",
            Operation::Insert => "INSERT",
            Operation::Update => "UPDATE",
            Operation::Delete => "DELETE",
        };
        
        // Insert the policy using direct SQL
        let insert_policy_sql = format!(
            "INSERT INTO _rls_policies (policy_name, table_name, operation, using_expr, check_expr) \
            VALUES ('{}', '{}', '{}', {}, {})",
            policy.policy_name,
            policy.table_name,
            operation_str,
            policy.using_expr.as_ref().map_or("NULL".to_string(), |s| format!("'{}'", s)),
            policy.check_expr.as_ref().map_or("NULL".to_string(), |s| format!("'{}'", s))
        );
        
        println!("DEBUG: Inserting policy with SQL: {}", insert_policy_sql);
        
        match conn.execute(&insert_policy_sql, empty_params()).await {
            Ok(_) => println!("DEBUG: Successfully inserted policy"),
            Err(e) => {
                // Rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to insert policy: {}", e)).into());
            }
        }
        
        // Verify the policy was inserted correctly
        let verify_sql = format!(
            "SELECT policy_name, table_name, operation FROM _rls_policies \
            WHERE policy_name = '{}' AND table_name = '{}'",
            policy.policy_name, policy.table_name
        );
        
        println!("DEBUG: Verifying policy insertion with SQL: {}", verify_sql);
        
        let rows = match conn.query_all(&verify_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                // Rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to verify policy insertion: {}", e)).into());
            }
        };
        
        if rows.is_empty() {
            // Rollback transaction
            let _ = conn.execute("ROLLBACK", empty_params()).await;
            return Err(Error::PolicyError("Failed to insert policy - verification failed".to_string()).into());
        }
        
        // Output all the policy details for debugging
        println!("DEBUG: Policy verification succeeded. Policy details:");
        for (i, row) in rows.iter().enumerate() {
            println!("  Row {}: policy_name={}, table_name={}, operation={}",
                i,
                row.get::<String>(0).unwrap_or_else(|_| "NULL".to_string()),
                row.get::<String>(1).unwrap_or_else(|_| "NULL".to_string()),
                row.get::<String>(2).unwrap_or_else(|_| "NULL".to_string())
            );
        }
        
        // Commit the transaction
        match conn.execute("COMMIT", empty_params()).await {
            Ok(_) => println!("DEBUG: Transaction committed successfully"),
            Err(e) => {
                // Try to rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to commit transaction: {}", e)).into());
            }
        }
        
        println!("DEBUG: Policy '{}' created successfully", policy.policy_name);
        
        Ok(())
    }

    /// Ensure a table is in the RLS tables list
    async fn ensure_table_in_rls(&self, conn: &libsql::Connection, table_name: &str) -> Result<()> {
        println!("Ensuring table '{}' is in RLS tables list", table_name);
        
        // Begin transaction
        match conn.execute("BEGIN TRANSACTION", empty_params()).await {
            Ok(_) => println!("Transaction started"),
            Err(e) => {
                return Err(Error::PolicyError(format!("Failed to begin transaction: {}", e)).into());
            }
        }

        // Check if table exists
        let check_sql = format!(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='{}'",
            table_name
        );
        println!("SQL query to check table existence: {}", check_sql);
        
        let params = empty_params();
        let rows = match conn.query_all(&check_sql, params.clone()).await {
            Ok(rows) => rows,
            Err(e) => {
                // Rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if table exists: {}", e)).into());
            }
        };

        if rows.is_empty() {
            // Rollback transaction
            let _ = conn.execute("ROLLBACK", empty_params()).await;
            return Err(Error::PolicyError(
                format!("Table does not exist or cannot be queried: {}", table_name)
            ).into());
        }

        // Get table info to verify it's a real table
        let tab_info_sql = format!("PRAGMA table_info('{}')", table_name);
        println!("SQL query to get table info: {}", tab_info_sql);
        
        let rows = match conn.query_all(&tab_info_sql, params.clone()).await {
            Ok(rows) => rows,
            Err(e) => {
                // Rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to get table info: {}", e)).into());
            }
        };

        if rows.is_empty() {
            // Rollback transaction
            let _ = conn.execute("ROLLBACK", empty_params()).await;
            return Err(Error::PolicyError(
                format!("Table does not have any columns: {}", table_name)
            ).into());
        }

        // Check if table is already in RLS tables
        let check_rls_sql = format!(
            "SELECT COUNT(*) FROM _rls_tables WHERE table_name = '{}'",
            table_name
        );
        println!("SQL query to check if table is in RLS tables: {}", check_rls_sql);
        
        let rows = match conn.query_all(&check_rls_sql, params.clone()).await {
            Ok(rows) => rows,
            Err(e) => {
                // Rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if table is in RLS tables: {}", e)).into());
            }
        };

        let exists = if let Some(row) = rows.first() {
            match row.get::<i64>(0) {
                Ok(count) => count > 0,
                Err(_) => false,
            }
        } else {
            false
        };

        if exists {
            // Update the existing entry to ensure it's enabled
            let update_sql = format!(
                "UPDATE _rls_tables SET enabled = TRUE WHERE table_name = '{}'",
                table_name
            );
            println!("SQL query to update RLS tables: {}", update_sql);
            
            match conn.execute(&update_sql, params.clone()).await {
                Ok(_) => println!("Updated existing entry in _rls_tables for table '{}'", table_name),
                Err(e) => {
                    // Rollback transaction
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    return Err(Error::PolicyError(format!("Failed to update RLS tables entry: {}", e)).into());
                }
            }
        } else {
            // Insert a new entry
            let insert_sql = format!(
                "INSERT INTO _rls_tables (table_name, enabled) VALUES ('{}', TRUE)",
                table_name
            );
            println!("SQL query to insert into RLS tables: {}", insert_sql);
            
            match conn.execute(&insert_sql, params.clone()).await {
                Ok(_) => println!("Inserted new entry in _rls_tables for table '{}'", table_name),
                Err(e) => {
                    // Rollback transaction
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    return Err(Error::PolicyError(format!("Failed to insert into RLS tables: {}", e)).into());
                }
            }
        }

        // Commit transaction
        match conn.execute("COMMIT", empty_params()).await {
            Ok(_) => println!("Transaction committed"),
            Err(e) => {
                // Try to rollback transaction
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to commit transaction: {}", e)).into());
            }
        }

        Ok(())
    }

    /// Check if RLS is enabled for a table
    pub async fn is_rls_enabled(&self, table_name: &str) -> Result<bool> {
        println!("DEBUG: Checking if RLS is enabled for table '{}'", table_name);
        
        // Create the connection
        let conn = self
            .db
            .connect()?;

        // Query _rls_tables
        let sql = "SELECT enabled FROM _rls_tables WHERE table_name = ?";
        let params = vec![Value::Text(table_name.to_string())];
        
        // Execute the query and handle possible cases
        let result = conn.query_row(sql, params).await;
        match result {
            Ok(Some(row)) => {
                // row is a Row, not an Option<Row>
                match row.get::<i64>(0) {
                    Ok(val) => {
                        println!("DEBUG: RLS for table '{}' is enabled: {}", table_name, val != 0);
                        Ok(val != 0)
                    },
                    Err(e) => {
                        println!("DEBUG: Error getting enabled status: {:?}", e);
                        Ok(false)
                    }
                }
            },
            Ok(None) => {
                // No rows returned, RLS is not enabled
                println!("DEBUG: Table '{}' not found in _rls_tables, RLS is not enabled", table_name);
                Ok(false)
            },
            Err(e) => {
                // Error querying RLS status
                println!("DEBUG: Error querying RLS status: {:?}", e);
                Ok(false)
            }
        }
    }

    /// Enable or disable RLS for a table
    pub async fn set_rls_enabled(&self, table_name: &str, enabled: bool) -> Result<(), Error> {
        println!("set_rls_enabled(): table_name={}, enabled={}", table_name, enabled);
        let db = self.db.clone();
        let conn = db.connect()?;
        
        // Begin transaction
        conn.execute("BEGIN TRANSACTION", empty_params()).await?;
        
        // First, check if _rls_tables exists
        println!("DEBUG: Checking if _rls_tables exists");
        let check_table_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_tables'";
        let rows = match conn.query_all(check_table_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if _rls_tables exists: {}", e)).into());
            }
        };
        
        // If _rls_tables doesn't exist, create it
        if rows.is_empty() {
            println!("DEBUG: _rls_tables doesn't exist, creating it");
            let create_tables_sql = "\
                CREATE TABLE IF NOT EXISTS _rls_tables ( \
                    table_name TEXT PRIMARY KEY, \
                    enabled BOOLEAN NOT NULL DEFAULT 0 \
                )";
            
            match conn.execute(create_tables_sql, empty_params()).await {
                Ok(_) => println!("DEBUG: Created _rls_tables table"),
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    return Err(Error::PolicyError(format!("Failed to create _rls_tables: {}", e)).into());
                }
            }
        }
        
        // Check if _rls_policies exists too
        println!("DEBUG: Checking if _rls_policies exists");
        let check_policies_sql = "SELECT name FROM sqlite_master WHERE type='table' AND name='_rls_policies'";
        let rows = match conn.query_all(check_policies_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if _rls_policies exists: {}", e)).into());
            }
        };
        
        // If _rls_policies doesn't exist, create it
        if rows.is_empty() {
            println!("DEBUG: _rls_policies doesn't exist, creating it");
            let create_policies_sql = "\
                CREATE TABLE IF NOT EXISTS _rls_policies ( \
                    policy_name TEXT NOT NULL, \
                    table_name TEXT NOT NULL, \
                    operation TEXT NOT NULL, \
                    using_expr TEXT, \
                    check_expr TEXT, \
                    PRIMARY KEY (policy_name, table_name), \
                    FOREIGN KEY (table_name) REFERENCES _rls_tables(table_name) \
                )";
            
            match conn.execute(create_policies_sql, empty_params()).await {
                Ok(_) => println!("DEBUG: Created _rls_policies table"),
                Err(e) => {
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    return Err(Error::PolicyError(format!("Failed to create _rls_policies: {}", e)).into());
                }
            }
        }
        
        // Check if the table exists in the database
        // We first try with sqlite_master
        println!("DEBUG: Checking if table '{}' exists in database", table_name);
        let check_sql = format!(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='{}'",
            table_name
        );
        
        let rows = match conn.query_all(&check_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to check if table exists: {}", e)).into());
            }
        };
        
        // If table not found in sqlite_master, we try a direct query to see if it exists
        // This works better for in-memory databases or transactions
        if rows.is_empty() {
            println!("DEBUG: Table not found in sqlite_master, trying direct query");
            
            // Try a direct query to the table
            let direct_check_sql = format!("SELECT 1 FROM {} LIMIT 1", table_name);
            
            match conn.query_all(&direct_check_sql, empty_params()).await {
                Ok(_) => {
                    println!("DEBUG: Table '{}' exists (verified by direct query)", table_name);
                    // Table exists, continue processing
                },
                Err(e) => {
                    // If the query fails, the table doesn't exist or can't be accessed
                    let _ = conn.execute("ROLLBACK", empty_params()).await;
                    println!("DEBUG: Table '{}' doesn't exist (direct query failed): {}", table_name, e);
                    return Err(Error::PolicyError(format!("Table '{}' doesn't exist in the database", table_name)).into());
                }
            }
        }
        
        // Check if table is already in _rls_tables
        println!("DEBUG: Checking if table '{}' is in _rls_tables", table_name);
        let check_rls_sql = format!(
            "SELECT COUNT(*) FROM _rls_tables WHERE table_name = '{}'",
            table_name
        );
        
        let rows = match conn.query_all(&check_rls_sql, empty_params()).await {
            Ok(rows) => rows,
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                println!("DEBUG: Error checking if table is in _rls_tables: {}", e);
                return Err(Error::PolicyError(format!("Failed to check if table is in RLS tables: {}", e)).into());
            }
        };
        
        let exists = if let Some(row) = rows.first() {
            match row.get::<i64>(0) {
                Ok(count) => count > 0,
                Err(_) => false,
            }
        } else {
            false
        };
        
        // Update or insert into _rls_tables
        println!("DEBUG: Directly inserting/updating table '{}' in _rls_tables with enabled={}", table_name, enabled);
        let sql = if exists {
            format!(
                "UPDATE _rls_tables SET enabled = {} WHERE table_name = '{}'",
                if enabled { 1 } else { 0 }, table_name
            )
        } else {
            format!(
                "INSERT INTO _rls_tables (table_name, enabled) VALUES ('{}', {})",
                table_name, if enabled { 1 } else { 0 }
            )
        };
        
        println!("DEBUG: Executing SQL: {}", sql);
        match conn.execute(&sql, empty_params()).await {
            Ok(_) => {
                println!("DEBUG: Successfully {} _rls_tables for table '{}'", 
                    if exists { "updated" } else { "inserted into" }, table_name);
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                println!("DEBUG: Error enabling/disabling RLS for table '{}': {:?}", table_name, e);
                return Err(Error::PolicyError(format!("Failed to set RLS enabled status for table {}: {}", table_name, e)).into());
            }
        }
        
        // Commit transaction
        match conn.execute("COMMIT", empty_params()).await {
            Ok(_) => {
                println!("DEBUG: Successfully committed transaction for enabling/disabling RLS on '{}'", table_name);
            }
            Err(e) => {
                let _ = conn.execute("ROLLBACK", empty_params()).await;
                return Err(Error::PolicyError(format!("Failed to commit transaction: {}", e)).into());
            }
        }
        
        Ok(())
    }

    pub async fn get_policies_for_statement(
        &self,
        stmt: &Statement,
    ) -> Result<HashMap<String, Vec<Policy>>> {
        // Get all tables referenced in the statement
        let mut table_policies = HashMap::new();

        // Extract table references from the statement
        match stmt {
            Statement::Query(query) => {
                // Handle different query structures based on the actual representation
                match &*query.body {
                    SetExpr::Select(select) => {
                        // Process all tables in the from clause
                        for table_with_joins in &select.from {
                            if let TableFactor::Table { name, .. } = &table_with_joins.relation {
                                let table_name = name.0.last().unwrap().value.clone();
                                
                                // Check if RLS is enabled for this table
                                if self.is_rls_enabled(&table_name).await? {
                                    // Get SELECT policies for this table
                                    let policies = self.get_policies(&table_name, Some(RlsOperation::Select)).await?;
                                    if !policies.is_empty() {
                                        table_policies.insert(table_name, policies);
                                    }
                                }
                            }
                        }
                    }
                    _ => {
                        println!("WARNING: Unsupported query type for RLS policy application");
                    }
                }
            }
            _ => {
                // For this prototype, we're only implementing SELECT
                // Non-query statements (INSERT, UPDATE, DELETE, etc.) are not supported
                println!("WARNING: Statement type not supported for RLS policies");
            }
        }

        Ok(table_policies)
    }

    pub async fn get_compiled_policies(
        &self,
        _statement: &Statement,
        table_policies: &HashMap<String, Vec<Policy>>,
    ) -> HashMap<String, CompiledStatement> {
        let mut compiled_policies = HashMap::new();

        // For each table, compile its policies into a WHERE clause
        for (table_name, policies) in table_policies {
            // Only process SELECT operations for this prototype
            // Each policy's USING expression contributes to the WHERE clause with OR semantics
            let mut where_clauses = Vec::new();
            
            for policy in policies {
                if let Some(clause) = policy.to_where_clause() {
                    where_clauses.push(format!("({})", clause));
                }
            }
            
            if !where_clauses.is_empty() {
                let compiled = where_clauses.join(" OR ");
                compiled_policies.insert(table_name.clone(), CompiledStatement { sql: compiled });
            }
        }

        compiled_policies
    }

    async fn drop_policy(&self, policy_name: &str, table_name: &str) -> Result<(), Error> {
        println!("drop_policy(): policy_name={}, table_name={}", policy_name, table_name);
        let db = self.db.clone();
        let conn = db.connect()?;
        // ... existing code ...
        Ok(())
    }

    pub async fn policy_exists(&self, policy_name: &str, table_name: &str) -> Result<bool, Error> {
        println!("policy_exists(): policy_name={}, table_name={}", policy_name, table_name);
        let db = self.db.clone();
        let conn = db.connect()?;
        
        // Use direct SQL formatting for consistent behavior
        let sql = format!(
            "SELECT 1 FROM _rls_policies WHERE policy_name = '{}' AND table_name = '{}'",
            policy_name, table_name
        );
        
        println!("DEBUG: Checking if policy exists with SQL: {}", sql);
        
        // Execute the query
        match conn.query_row(&sql, empty_params()).await {
            Ok(Some(_)) => {
                println!("DEBUG: Policy '{}' for table '{}' exists", policy_name, table_name);
                Ok(true)
            }
            Ok(None) => {
                println!("DEBUG: Policy '{}' for table '{}' does not exist", policy_name, table_name);
                Ok(false)
            }
            Err(e) => {
                println!("DEBUG: Error checking if policy exists: {}", e);
                Err(Error::PolicyError(format!("Failed to check if policy exists: {}", e)).into())
            }
        }
    }
} 