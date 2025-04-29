use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("SQL parsing error: {0}")]
    SqlParse(#[from] sqlparser::parser::ParserError),
    
    #[error("Database error: {0}")]
    Database(#[from] libsql::Error),
    
    #[error("Unsupported SQL feature: {0}")]
    UnsupportedSql(String),
    
    #[error("Policy error: {0}")]
    Policy(String),
    
    #[error("Tokenizer error: {0}")]
    TokenizerError(#[from] sqlparser::tokenizer::TokenizerError),
} 