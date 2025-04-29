use crate::{policy::Policy, Error, Result};
use sqlparser::ast::{
    Expr, Select, SetExpr, Statement, TableFactor, Value,
};
use sqlparser::dialect::SQLiteDialect;
use sqlparser::parser::Parser;

/// Parse an SQL statement into a Statement AST
pub fn parse_sql(sql: &str) -> Result<Statement> {
    let dialect = SQLiteDialect {};
    let mut statements = Parser::parse_sql(&dialect, sql)?;

    if statements.len() != 1 {
        return Err(Error::UnsupportedSql(
            "Only single SQL statements are supported".to_string(),
        ));
    }

    Ok(statements.pop().unwrap())
}

/// Extract the names of all tables referenced in a SELECT statement
pub fn extract_table_references(statement: &Statement) -> Vec<String> {
    let mut tables = Vec::new();

    if let Statement::Query(query) = statement {
        if let SetExpr::Select(select) = &*query.body {
            for table_with_joins in &select.from {
                if let TableFactor::Table { name, .. } = &table_with_joins.relation {
                    tables.push(name.to_string());
                }
            }
        }
    }

    tables
}

/// Apply RLS policies to a SELECT statement
pub fn apply_rls_to_select(statement: &mut Statement, policies: &[Policy]) -> Result<()> {
    if let Statement::Query(query) = statement {
        if let SetExpr::Select(select) = &mut *query.body {
            for policy in policies {
                if let Some(using_expr) = &policy.using_expr {
                    apply_policy_to_select(select, using_expr)?;
                }
            }
        }
    }

    Ok(())
}

/// Apply a policy expression to a SELECT statement
fn apply_policy_to_select(select: &mut Box<Select>, policy_expr: &str) -> Result<()> {
    // Parse the policy expression
    let policy_condition = parse_policy_expression(policy_expr)?;
    
    // If there's an existing WHERE clause, AND it with the policy
    if let Some(where_clause) = &select.selection {
        let new_where = Expr::BinaryOp {
            left: Box::new(where_clause.clone()),
            op: sqlparser::ast::BinaryOperator::And,
            right: Box::new(policy_condition),
        };
        select.selection = Some(new_where);
    } else {
        // Otherwise, set the policy as the WHERE clause
        select.selection = Some(policy_condition);
    }

    Ok(())
}

/// Parse a policy expression string into an Expr AST
fn parse_policy_expression(expr_str: &str) -> Result<Expr> {
    // For the prototype, we'll handle simple equality comparisons
    // Format: "column_name = value"
    let parts: Vec<&str> = expr_str.trim().split('=').collect();
    if parts.len() != 2 {
        return Err(Error::Policy(format!(
            "Only simple equality expressions are supported, got: {}", 
            expr_str
        )));
    }

    let column = parts[0].trim();
    let value = parts[1].trim();

    // Try to parse value as a number first
    if let Ok(num) = value.parse::<i64>() {
        return Ok(Expr::BinaryOp {
            left: Box::new(Expr::Identifier(sqlparser::ast::Ident::new(column))),
            op: sqlparser::ast::BinaryOperator::Eq,
            right: Box::new(Expr::Value(Value::Number(num.to_string(), false))),
        });
    }
    
    // Otherwise, treat as string
    let value_str = value.trim_matches('\'').trim_matches('"');
    Ok(Expr::BinaryOp {
        left: Box::new(Expr::Identifier(sqlparser::ast::Ident::new(column))),
        op: sqlparser::ast::BinaryOperator::Eq,
        right: Box::new(Expr::Value(Value::SingleQuotedString(value_str.to_string()))),
    })
}

/// Compile an AST back to SQL
pub fn compile_ast_to_sql(statement: &Statement) -> String {
    statement.to_string()
} 