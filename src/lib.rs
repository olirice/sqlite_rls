mod policy;
mod error;
mod connection;

pub use connection::RlsConnection;
pub use error::Error;
pub use policy::{Policy, PolicyManager};

pub type Result<T> = std::result::Result<T, Error>; 