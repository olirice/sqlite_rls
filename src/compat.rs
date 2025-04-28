use anyhow::{anyhow, Result};
use libsql::{Connection, Database, Builder, Statement, Value};
use std::path::Path;
use std::sync::Arc;

/// Wrapper around Database to provide some compatibility functions
pub struct DatabaseWrapper {
    db: Arc<Database>,
}

impl DatabaseWrapper {
    /// Create a new database wrapper
    pub fn new(db: Arc<Database>) -> Self {
        Self { db }
    }

    /// Create a new wrapper with an opened database
    pub async fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let url = path.as_ref().to_string_lossy().to_string();
        let db = Builder::new_local(&url).build().await?;
        Ok(Self::new(Arc::new(db)))
    }

    /// Get a connection to the database
    pub fn connect(&self) -> Result<Connection> {
        Ok(self.db.connect()?)
    }

    /// Get a reference to the underlying database
    pub fn inner(&self) -> Arc<Database> {
        self.db.clone()
    }

    /// Clone this wrapper and get a new reference to the same database
    pub fn clone(&self) -> Self {
        Self { db: self.db.clone() }
    }
}

/// Extension trait for Connection to provide functionality similar to previous versions
pub trait ConnectionExt {
    /// Execute a query and return a single row (or None if no rows)
    async fn query_row<P>(&self, sql: &str, params: P) -> Result<Option<libsql::Row>>
    where
        P: IntoParams;

    /// Execute a query and return all rows
    async fn query_all<P>(&self, sql: &str, params: P) -> Result<Vec<libsql::Row>>
    where
        P: IntoParams;

    /// Execute a statement that doesn't return rows
    async fn execute<P>(&self, sql: &str, params: P) -> Result<()>
    where
        P: IntoParams;
}

impl ConnectionExt for Connection {
    async fn query_row<P>(&self, sql: &str, params: P) -> Result<Option<libsql::Row>>
    where
        P: IntoParams,
    {
        let params_vec = params.to_params()?;
        
        let mut rows = self.query(sql, params_vec).await?;
        
        if let Some(row) = rows.next().await? {
            return Ok(Some(row));
        }
        
        Ok(None)
    }

    async fn query_all<P>(&self, sql: &str, params: P) -> Result<Vec<libsql::Row>>
    where
        P: IntoParams,
    {
        let params_vec = params.to_params()?;
        
        let mut rows = self.query(sql, params_vec).await?;
        
        let mut result = Vec::new();
        while let Some(row) = rows.next().await? {
            result.push(row);
        }
        
        Ok(result)
    }

    async fn execute<P>(&self, sql: &str, params: P) -> Result<()>
    where
        P: IntoParams,
    {
        let params_vec = params.to_params()?;
        
        self.execute(sql, params_vec).await?;
        
        Ok(())
    }
}

/// Trait for converting types to query parameters
pub trait IntoParams {
    fn to_params(self) -> Result<Vec<Value>>;
}

/// Helper type-annotated empty params
pub type EmptyParams = [libsql::Value; 0];

/// Helper function to get an empty array with the correct type annotation
pub const fn empty_params() -> EmptyParams {
    []
}

// Implementation for tuples
impl<T: Into<Value>> IntoParams for (T,) {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![self.0.into()])
    }
}

impl<T1: Into<Value>, T2: Into<Value>> IntoParams for (T1, T2) {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![self.0.into(), self.1.into()])
    }
}

impl<T1: Into<Value>, T2: Into<Value>, T3: Into<Value>> IntoParams for (T1, T2, T3) {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![self.0.into(), self.1.into(), self.2.into()])
    }
}

// Implementation for arrays
impl<T: Into<Value> + Clone> IntoParams for [T; 0] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(Vec::new())
    }
}

impl<T: Into<Value> + Clone> IntoParams for [T; 1] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![self[0].clone().into()])
    }
}

impl<T: Into<Value> + Clone> IntoParams for [T; 2] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![self[0].clone().into(), self[1].clone().into()])
    }
}

impl<T: Into<Value> + Clone> IntoParams for [T; 3] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![
            self[0].clone().into(),
            self[1].clone().into(),
            self[2].clone().into(),
        ])
    }
}

// Implementation for references to arrays
impl<T: Into<Value> + Clone> IntoParams for &[T; 0] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(Vec::new())
    }
}

impl<T: Into<Value> + Clone> IntoParams for &[T; 1] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![self[0].clone().into()])
    }
}

impl<T: Into<Value> + Clone> IntoParams for &[T; 2] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![self[0].clone().into(), self[1].clone().into()])
    }
}

impl<T: Into<Value> + Clone> IntoParams for &[T; 3] {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![
            self[0].clone().into(),
            self[1].clone().into(),
            self[2].clone().into(),
        ])
    }
}

// Implementation for string references to handle &str
impl IntoParams for &str {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![Value::Text(self.to_string())])
    }
}

impl IntoParams for &String {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![Value::Text(self.clone())])
    }
}

// Implementation for strings
impl IntoParams for String {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![Value::Text(self)])
    }
}

// Implementation for boolean
impl IntoParams for bool {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![Value::Integer(if self { 1 } else { 0 })])
    }
}

impl IntoParams for &bool {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![Value::Integer(if *self { 1 } else { 0 })])
    }
}

// Implementation for integers
impl IntoParams for i64 {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![Value::Integer(self)])
    }
}

impl IntoParams for &i64 {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(vec![Value::Integer(*self)])
    }
}

// Implementation for Option
impl<T: IntoParams> IntoParams for Option<T> {
    fn to_params(self) -> Result<Vec<Value>> {
        match self {
            Some(t) => t.to_params(),
            None => Ok(vec![Value::Null]),
        }
    }
}

// Implementation for standard Vec
impl<T: Into<Value> + Clone> IntoParams for Vec<T> {
    fn to_params(self) -> Result<Vec<Value>> {
        self.into_iter().map(|t| Ok(t.into())).collect()
    }
}

// Empty implementation
impl IntoParams for () {
    fn to_params(self) -> Result<Vec<Value>> {
        Ok(Vec::new())
    }
} 