use anyhow::Result;
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser as SqlParser;
use sqlparser::tokenizer::Tokenizer;
use sqlparser::ast::{Statement, Value, Expr, Ident};
use crate::error::Error;

/// SQL Parser for libSQL that handles both standard SQL and RLS-specific syntax
pub struct Parser {
    dialect: SQLiteDialect,
}

impl Parser {
    /// Create a new parser
    pub fn new() -> Self {
        Self {
            dialect: SQLiteDialect {},
        }
    }

    /// Parse SQL string into an AST
    pub fn parse_sql(&self, sql: &str) -> Result<sqlparser::ast::Statement> {
        // Tokenize the SQL
        let _tokens = Tokenizer::new(&self.dialect, sql).tokenize().map_err(|e| Error::ParsingError(e.to_string()))?;
        
        // Parse the tokens into a statement
        let dialect = SQLiteDialect {};
        let ast = SqlParser::parse_sql(&dialect, sql).map_err(|e| Error::ParsingError(e.to_string()))?;
        
        if ast.len() != 1 {
            return Err(Error::ParsingError("Expected exactly one SQL statement".to_string()).into());
        }
        
        Ok(ast.into_iter().next().unwrap())
    }

    /// Parse SQL statements including potentially RLS-specific statements
    /// Returns a Vec of Statement which could be either SQL or RLS statements
    pub fn parse_sql_with_rls(&self, sql: &str) -> Result<Vec<Statement>> {
        // Split the input on semicolons
        let statements = sql.split(';')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        
        // For real implementation, you would need proper SQL parsing to handle 
        // semicolons inside quoted strings, comments, etc.
        
        let mut result = Vec::new();
        for stmt_str in statements {
            // Try to parse as regular SQL first
            match SqlParser::parse_sql(&self.dialect, stmt_str) {
                Ok(stmts) => {
                    // Successfully parsed as regular SQL
                    result.extend(stmts);
                },
                Err(_) => {
                    // Not regular SQL, try to parse as RLS statement
                    if stmt_str.to_uppercase().contains("ROW LEVEL SECURITY") || 
                       stmt_str.to_uppercase().contains("CREATE POLICY") ||
                       stmt_str.to_uppercase().contains("DROP POLICY") {
                        // Create a custom Statement type for the RLS statement
                        let _rls_stmt = self.parse_rls_statement(stmt_str)?;
                        
                        // Create a simple select statement as a placeholder
                        // The real implementation would properly handle RLS statements
                        let mut query = sqlparser::ast::Query {
                            with: None,
                            body: Box::new(sqlparser::ast::SetExpr::Values(sqlparser::ast::Values {
                                explicit_row: false,
                                rows: vec![vec![sqlparser::ast::Expr::Value(
                                    sqlparser::ast::Value::SingleQuotedString(format!("RLS: {}", stmt_str))
                                )]],
                            })),
                            order_by: vec![],
                            limit: None,
                            offset: None,
                            fetch: None,
                            locks: vec![],
                        };
                        
                        result.push(Statement::Query(Box::new(query)));
                    } else {
                        return Err(Error::ParsingError(format!("Failed to parse statement: {}", stmt_str)).into());
                    }
                }
            }
        }
        
        Ok(result)
    }

    /// Parse RLS-specific SQL statements (like CREATE POLICY) that aren't part of standard SQL
    pub fn parse_rls_statement(&self, sql: &str) -> Result<RlsStatement> {
        // This is a simple approach - in a real implementation, you'd build a proper parser
        // for RLS statements or extend sqlparser to handle them

        if sql.trim().to_uppercase().starts_with("ALTER TABLE") && sql.to_uppercase().contains("ROW LEVEL SECURITY") {
            return self.parse_alter_table_rls(sql);
        }
        
        if sql.trim().to_uppercase().starts_with("CREATE POLICY") {
            return self.parse_create_policy(sql);
        }
        
        if sql.trim().to_uppercase().starts_with("DROP POLICY") {
            return self.parse_drop_policy(sql);
        }

        Err(Error::ParsingError(format!("Not an RLS statement: {}", sql)).into())
    }

    // Parse ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY
    fn parse_alter_table_rls(&self, sql: &str) -> Result<RlsStatement> {
        let sql_upper = sql.to_uppercase();
        
        // Check if it's ENABLE or DISABLE
        let enable = if sql_upper.contains("ENABLE ROW LEVEL SECURITY") {
            true
        } else if sql_upper.contains("DISABLE ROW LEVEL SECURITY") {
            false
        } else {
            return Err(Error::ParsingError("Invalid ALTER TABLE RLS syntax".to_string()).into());
        };
        
        // Extract table name - this is a simplified approach
        // A real implementation would use proper SQL parsing
        let table_start = sql_upper.find("TABLE").ok_or_else(|| 
            Error::ParsingError("Could not find TABLE in ALTER TABLE statement".to_string()))?;
        
        let table_section = &sql_upper[table_start + 5..];
        let table_end = table_section.find("ENABLE").unwrap_or_else(|| 
            table_section.find("DISABLE").unwrap_or(table_section.len()));
        
        let table_name = table_section[..table_end].trim().to_string();
        
        Ok(RlsStatement::AlterTableRls { 
            table_name, 
            enable 
        })
    }

    // Parse CREATE POLICY statement
    fn parse_create_policy(&self, sql: &str) -> Result<RlsStatement> {
        // This is a simplified parser - a real implementation would use a grammar-based approach
        
        let sql_upper = sql.to_uppercase();
        
        // Extract policy name
        let policy_start = sql_upper.find("POLICY").ok_or_else(|| 
            Error::ParsingError("Could not find POLICY in CREATE POLICY statement".to_string()))?;
        
        let policy_section = &sql[policy_start + 6..];
        let policy_end = policy_section.to_uppercase().find("ON").unwrap_or(policy_section.len());
        let policy_name = policy_section[..policy_end].trim().to_string();
        
        // Extract table name
        let on_idx = sql_upper.find("ON").ok_or_else(|| 
            Error::ParsingError("Could not find ON in CREATE POLICY statement".to_string()))?;
        
        let table_section = &sql[on_idx + 2..];
        let table_end = table_section.to_uppercase().find("FOR").unwrap_or(table_section.len());
        let table_name = table_section[..table_end].trim().to_string();
        
        // Determine operation (SELECT, INSERT, etc.)
        let operation = if sql_upper.contains("FOR SELECT") {
            RlsOperation::Select
        } else if sql_upper.contains("FOR INSERT") {
            RlsOperation::Insert
        } else if sql_upper.contains("FOR UPDATE") {
            RlsOperation::Update
        } else if sql_upper.contains("FOR DELETE") {
            RlsOperation::Delete
        } else if sql_upper.contains("FOR ALL") {
            RlsOperation::All
        } else {
            RlsOperation::All // Default to all if not specified
        };
        
        // Extract USING expression
        let using_expr = if let Some(using_idx) = sql_upper.find("USING") {
            let using_section = &sql[using_idx + 5..];
            // If there's a CHECK clause, use that as the end boundary
            let end_idx = using_section.to_uppercase().find("CHECK").unwrap_or(using_section.len());
            Some(using_section[..end_idx].trim().to_string())
        } else {
            None
        };
        
        // Extract CHECK expression
        let check_expr = if let Some(check_idx) = sql_upper.find("CHECK") {
            let check_section = &sql[check_idx + 5..];
            Some(check_section.trim().to_string())
        } else {
            None
        };
        
        Ok(RlsStatement::CreatePolicy {
            policy_name,
            table_name,
            operation,
            using_expr,
            check_expr,
        })
    }

    // Parse DROP POLICY statement
    fn parse_drop_policy(&self, sql: &str) -> Result<RlsStatement> {
        let sql_upper = sql.to_uppercase();
        
        // Extract policy name
        let policy_start = sql_upper.find("POLICY").ok_or_else(|| 
            Error::ParsingError("Could not find POLICY in DROP POLICY statement".to_string()))?;
        
        let policy_section = &sql[policy_start + 6..];
        let policy_end = policy_section.to_uppercase().find("ON").unwrap_or(policy_section.len());
        let policy_name = policy_section[..policy_end].trim().to_string();
        
        // Extract table name
        let table_name = if let Some(on_idx) = sql_upper.find("ON") {
            let table_section = &sql[on_idx + 2..];
            table_section.trim().to_string()
        } else {
            return Err(Error::ParsingError("Could not find ON in DROP POLICY statement".to_string()).into());
        };
        
        Ok(RlsStatement::DropPolicy {
            policy_name,
            table_name,
        })
    }
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

/// Statements that are specific to Row Level Security
#[derive(Debug, Clone, PartialEq)]
pub enum RlsStatement {
    /// ALTER TABLE ... ENABLE/DISABLE ROW LEVEL SECURITY
    AlterTableRls {
        /// Table to enable or disable RLS on
        table_name: String,
        /// Whether to enable (true) or disable (false) RLS
        enable: bool,
    },
    
    /// CREATE POLICY statement
    CreatePolicy {
        /// Name of the policy
        policy_name: String,
        /// Table the policy applies to
        table_name: String,
        /// Operation the policy applies to (SELECT, INSERT, etc.)
        operation: RlsOperation,
        /// USING expression (applied to existing rows)
        using_expr: Option<String>,
        /// CHECK expression (applied to new/modified rows)
        check_expr: Option<String>,
    },
    
    /// DROP POLICY statement
    DropPolicy {
        /// Name of the policy to drop
        policy_name: String,
        /// Table the policy applies to
        table_name: String,
    },
}

/// Types of operations that policies can apply to
#[derive(Debug, Clone, PartialEq)]
pub enum RlsOperation {
    /// SELECT operations
    Select,
    /// INSERT operations
    Insert,
    /// UPDATE operations
    Update,
    /// DELETE operations
    Delete,
    /// All operations
    All,
}

impl std::fmt::Display for RlsOperation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RlsOperation::Select => write!(f, "SELECT"),
            RlsOperation::Insert => write!(f, "INSERT"),
            RlsOperation::Update => write!(f, "UPDATE"),
            RlsOperation::Delete => write!(f, "DELETE"),
            RlsOperation::All => write!(f, "ALL"),
        }
    }
}

impl RlsOperation {
    /// Create an RlsOperation from a string
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        match s.to_uppercase().as_str() {
            "SELECT" => Ok(RlsOperation::Select),
            "INSERT" => Ok(RlsOperation::Insert),
            "UPDATE" => Ok(RlsOperation::Update),
            "DELETE" => Ok(RlsOperation::Delete),
            "ALL" => Ok(RlsOperation::All),
            _ => Err(anyhow::anyhow!("Invalid RLS operation: {}", s)),
        }
    }
} 