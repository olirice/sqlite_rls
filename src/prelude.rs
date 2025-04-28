// Re-export important types and traits for easy use
pub use crate::compat::{ConnectionExt, DatabaseWrapper, IntoParams};
pub use crate::error::Error;
pub use crate::parser::Parser;
pub use crate::policy::{Policy, PolicyManager};
pub use crate::rewriter::QueryRewriter;
pub use crate::RlsExtension; 