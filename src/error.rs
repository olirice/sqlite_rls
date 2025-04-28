use thiserror::Error;

/// Custom error types for the libSQL RLS extension
#[derive(Error, Debug)]
pub enum Error {
    /// Error that occurs during SQL parsing
    #[error("SQL parsing error: {0}")]
    ParsingError(String),

    /// Error that occurs during AST rewriting
    #[error("AST rewriting error: {0}")]
    RewritingError(String),

    /// Error that occurs during policy application
    #[error("Policy application error: {0}")]
    PolicyError(String),

    /// Error with libSQL itself
    #[error("libSQL error: {0}")]
    LibSqlError(#[from] libsql::Error),

    /// Error with SQL parser
    #[error("SQL parser error: {0}")]
    SqlParserError(#[from] sqlparser::parser::ParserError),

    /// Generic error when a specific type is not appropriate
    #[error("{0}")]
    Other(String),
}

/// Result type alias for libSQL RLS operations
pub type Result<T> = std::result::Result<T, Error>; 