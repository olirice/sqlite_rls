# libSQL Row Level Security (RLS) Extension

This extension adds PostgreSQL-like Row Level Security capabilities to libSQL. It performs RLS policy application through AST manipulation rather than string manipulation, ensuring robust and reliable security enforcement.

## Overview

Row Level Security (RLS) allows database administrators to define security policies that restrict which rows users can access in database tables. This extension implements RLS for libSQL by intercepting and rewriting SQL queries to include the appropriate security conditions based on the current user context.

### Key Features

- PostgreSQL-compatible RLS syntax
- AST-based policy enforcement for reliable security
- Support for complex policy conditions with boolean expressions
- Automatic policy application to SELECT, INSERT, UPDATE, and DELETE queries
- Multiple policy support with OR semantics for combining conditions
- Admin bypass capability for superusers
- Compatible with libSQL 0.9.x using the async APIs

## Architecture

The RLS extension consists of several interconnected components:

### Core Components

1. **RlsExtension**: The main entry point that initializes the RLS system and provides access to the rewriter.

2. **QueryRewriter**: Intercepts SQL statements, analyzes them, and rewrites them to include RLS conditions.

3. **PolicyManager**: Manages the creation, storage, and retrieval of RLS policies from the database.

4. **AstManipulator**: Modifies the Abstract Syntax Tree (AST) of SQL statements to apply security conditions.

5. **Parser**: Handles the parsing of SQL statements, including RLS-specific statements like `CREATE POLICY`.

### Database Schema

The extension creates and manages several metadata tables:

- `_rls_tables`: Tracks which tables have RLS enabled
- `_rls_policies`: Stores policy definitions including names, conditions, and operations
- `_rls_current_user`: Stores the current user context for policy evaluation

## How It Works

### Policy Application Process

1. **Query Interception**: When a SQL query is executed, it's intercepted by the `QueryRewriter`.

2. **AST Parsing**: The query is parsed into an Abstract Syntax Tree.

3. **Table Identification**: The rewriter identifies which tables are referenced in the query.

4. **Policy Retrieval**: For each table with RLS enabled, relevant policies are retrieved.

5. **Condition Generation**: Policy conditions are combined using OR semantics.

6. **AST Modification**: The query's AST is modified to include additional WHERE conditions.

7. **Query Execution**: The rewritten query is executed, returning only the rows the user is authorized to access.

### Admin Bypass

Administrators can bypass RLS using special policies:

1. The rewriter first checks for admin bypass policies.
2. If the current user is an admin, the original query is executed without modification.
3. Otherwise, normal RLS policies are applied.

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
    let mut rls = RlsExtension::new(db_arc.clone());
    rls.initialize().await?;
    
    // Create a policy manager
    let policy_manager = PolicyManager::new(db_arc.clone());
    
    // Enable RLS on your table
    policy_manager.set_rls_enabled("posts", true).await?;
    
    // Set up user context
    let conn = db_arc.connect()?;
    conn.execute(
        "CREATE TABLE IF NOT EXISTS _rls_current_user (id INTEGER, role TEXT)",
        empty_params(),
    ).await?;
    conn.execute(
        "DELETE FROM _rls_current_user",
        empty_params(),
    ).await?;
    conn.execute(
        "INSERT INTO _rls_current_user (id, role) VALUES (?, ?)",
        (2, "user"),
    ).await?;
    
    // Create an ownership policy
    let policy = Policy::new(
        "posts_ownership",
        "posts",
        RlsOperation::Select,
        Some("user_id = (SELECT id FROM _rls_current_user LIMIT 1)".to_string()),
        None,
    );
    
    policy_manager.create_policy(&policy).await?;
    
    // Create a public visibility policy (OR semantics)
    let public_policy = Policy::new(
        "posts_public_visibility",
        "posts",
        RlsOperation::Select,
        Some("is_public = 1".to_string()),
        None,
    );
    
    policy_manager.create_policy(&public_policy).await?;
    
    // Create an admin bypass policy
    let admin_policy = Policy::new(
        "posts_admin_bypass",
        "posts",
        RlsOperation::Select,
        Some("(SELECT role FROM _rls_current_user LIMIT 1) = 'admin'".to_string()),
        None,
    );
    
    policy_manager.create_policy(&admin_policy).await?;
    
    // Execute a query with RLS
    let sql = "SELECT * FROM posts";
    let dialect = sqlparser::dialect::SQLiteDialect {};
    let statements = sqlparser::parser::Parser::parse_sql(&dialect, sql)?;
    
    // Rewrite the query with RLS
    let rewriter = rls.rewriter();
    let rewritten = rewriter.rewrite(statements[0].clone()).await?;
    
    // Execute the rewritten query
    let rewritten_sql = rewritten.to_string();
    println!("Rewritten SQL: {}", rewritten_sql);
    
    let rows = conn.query_all(&rewritten_sql, empty_params()).await?;
    println!("Found {} rows", rows.len());
    
    Ok(())
}
```

### SQL API

The extension provides a SQL API for managing RLS policies:

```sql
-- Enable RLS on a table
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;

-- Create an ownership policy
CREATE POLICY posts_ownership ON posts
    FOR SELECT
    USING (user_id = (SELECT id FROM _rls_current_user LIMIT 1));

-- Create a public visibility policy
CREATE POLICY posts_public_visibility ON posts
    FOR SELECT
    USING (is_public = 1);

-- Create an admin bypass policy
CREATE POLICY posts_admin_bypass ON posts
    FOR SELECT
    USING ((SELECT role FROM _rls_current_user LIMIT 1) = 'admin');

-- Disable RLS on a table
ALTER TABLE posts DISABLE ROW LEVEL SECURITY;

-- Drop a policy
DROP POLICY posts_ownership ON posts;
```

## Real-World Example: Blog Application

Consider a blog application with users, posts, and comments:

```sql
-- Create tables
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    role TEXT NOT NULL
);

CREATE TABLE posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    is_public BOOLEAN NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE comments (
    id INTEGER PRIMARY KEY,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Enable RLS
ALTER TABLE posts ENABLE ROW LEVEL SECURITY;
ALTER TABLE comments ENABLE ROW LEVEL SECURITY;

-- Create policies for posts
CREATE POLICY posts_ownership ON posts
    FOR SELECT
    USING (user_id = (SELECT id FROM _rls_current_user LIMIT 1));

CREATE POLICY posts_public_visibility ON posts
    FOR SELECT
    USING (is_public = 1);

CREATE POLICY posts_admin_bypass ON posts
    FOR SELECT
    USING ((SELECT role FROM _rls_current_user LIMIT 1) = 'admin');

-- Create policies for comments
CREATE POLICY comments_ownership ON comments
    FOR SELECT
    USING (user_id = (SELECT id FROM _rls_current_user LIMIT 1));

CREATE POLICY comments_on_visible_posts ON comments
    FOR SELECT
    USING (post_id IN (SELECT id FROM posts));
```

With these policies:
- Regular users see only their own posts and public posts
- Users see only comments on posts they can access
- Admins can see all posts and comments

## Implementation Details

### Query Rewriting Flow

1. User executes: `SELECT * FROM posts`
2. Query is parsed into an AST
3. Tables with RLS are identified (`posts` in this case)
4. Admin bypass policy is checked first
   - If user is admin, original query is returned
   - Otherwise, continue with regular policies
5. Policy conditions are collected and combined:
   `(user_id = (SELECT id FROM _rls_current_user LIMIT 1)) OR (is_public = 1)`
6. Query is rewritten: 
   `SELECT * FROM posts WHERE (user_id = (SELECT id FROM _rls_current_user LIMIT 1)) OR (is_public = 1)`
7. Rewritten query is executed, returning only authorized rows

### Policy Evaluation

Policies are evaluated using OR semantics within the same operation type:
- Multiple SELECT policies are combined with OR
- If any policy condition is met, the row is included in results

## Testing

The project includes comprehensive test suites:

```bash
# Run all tests
cargo test

# Run specific test
cargo test test_admin_bypass_policy
cargo test test_ownership_policy
cargo test test_public_visibility_policy
```

## Project Structure

- `src/lib.rs` - Main library and extension implementation
- `src/ast.rs` - AST manipulation utilities
- `src/parser.rs` - SQL parser with RLS extensions
- `src/policy.rs` - Policy management and storage
- `src/rewriter.rs` - SQL query rewriting engine
- `src/compat.rs` - Compatibility layer for libSQL API
- `tests/` - Integration tests for various policy scenarios

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 