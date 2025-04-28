# libSQL Row Level Security (RLS) Extension

This extension adds PostgreSQL-like Row Level Security capabilities to libSQL. It performs RLS policy application through AST manipulation rather than string manipulation, ensuring robust and reliable security enforcement.

## Current Status

This project has been updated to work with the latest libSQL API (0.9.x) using the new async APIs and Builder pattern. The implementation uses Arc for sharing database connections safely.

## Features

- PostgreSQL-compatible RLS syntax
- AST-based policy enforcement
- Support for complex policy conditions
- Automatic policy application to queries
- Compatible with libSQL 0.9.x

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/libsql_rls.git
cd libsql_rls

# Build the extension
cargo build --release
```

## Usage

### Integration with Your Application

```rust
use rls::prelude::*;
use rls::policy::{Policy, PolicyManager};
use rls::parser::RlsOperation;
use libsql::{Builder, Database};
use anyhow::Result;
use std::sync::Arc;

#[tokio::main]
async fn example() -> Result<()> {
    // Open a database using the Builder pattern
    let db = Builder::new_local("my_database.db")
        .build()
        .await?;
    
    // Initialize RLS extension with Arc for thread safety
    let db_arc = Arc::new(db);
    let rls = RlsExtension::new(db_arc.clone());
    rls.initialize().await?;
    
    // Create a policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // Enable RLS on your table
    policy_manager.set_rls_enabled("my_table", true).await?;
    
    // Create a policy that filters rows by user ID
    let policy = Policy::new(
        "user_policy",
        "my_table",
        RlsOperation::Select,
        Some("user_id = current_user_id()".to_string()),
        None,
    );
    
    policy_manager.create_policy(&policy).await?;
    
    // Queries will automatically respect RLS policies
    let conn = db_arc.connect()?;
    let rows = conn.query_all("SELECT * FROM my_table", empty_params()).await?;
    
    Ok(())
}
```

### RLS Syntax

```sql
-- Enable RLS on a table
ALTER TABLE my_table ENABLE ROW LEVEL SECURITY;

-- Create a policy
CREATE POLICY my_policy ON my_table
    FOR SELECT
    USING (user_id = current_user());
```

## Testing

The project includes comprehensive test suites:

```bash
# Run all tests
cargo test

# Run specific test category
cargo test unit
cargo test ast
cargo test rls
```

## Project Structure

- `src/lib.rs` - Main library and extension implementation
- `src/ast.rs` - AST manipulation utilities
- `src/parser.rs` - SQL parser with RLS extensions
- `src/policy.rs` - Policy management
- `src/rewriter.rs` - SQL rewriting to apply RLS
- `src/compat.rs` - Compatibility layer for libSQL API
- `tests/unit_tests.rs` - Core functionality tests
- `tests/ast_tests.rs` - AST transformation tests
- `tests/rls_tests.rs` - Integration tests

## Implementation Notes

- The extension uses `Arc<Database>` for safe sharing of database connections
- All database operations use the async API with proper awaiting
- The `DatabaseWrapper` provides a convenient interface for working with the database
- Proper error handling is implemented throughout the codebase

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 