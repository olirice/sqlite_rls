# LibSQL Row Level Security (RLS) Wrapper

This project provides a row-level security implementation for LibSQL, inspired by Postgres RLS.

## Features

- Create and manage security policies
- Parse `CREATE POLICY` statements
- Store policies in a dedicated RLS metadata table
- Intercept SQL statements to apply RLS rules
- Automatic initialization of RLS metadata tables

## Implementation Details

The implementation consists of several components:

1. **RlsConnection**: A wrapper around the LibSQL connection that intercepts SQL statements
2. **Policy Manager**: Handles the creation and management of security policies
3. **SQL Parsing**: Basic regex-based parsing for CREATE POLICY statements

## Usage

```rust
// Create a database connection
let db = Database::open_in_memory()?;
let conn = db.connect()?;

// Create an RLS connection with automatic table initialization
let rls_conn = RlsConnection::new_initialized(conn).await?;

// Create policies
rls_conn.execute(
    "CREATE POLICY user_policy ON users USING (user_id = current_user_id())",
    params![]
).await?;
```

## Interactive Session

For a hands-on demonstration of RLS in action, run the included interactive shell:

This demo will:
1. Create a fresh database with sample tables and data
2. Apply RLS policies for tenant isolation
3. Provide an interactive SQL shell to experiment with policies


```bash
cargo run --bin test_with_rls
```

You can also try creating different policies to experiment with various access control patterns.

Default Setup
```
   Compiling libsql_rls v0.1.0 (/Users/oliverrice/Documents/supabase/libsql_rls)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.66s
     Running `target/debug/rls_repl`
LibSQL Row Level Security (RLS) Demo
====================================
Setting up new database: demo_rls.db

Database initialized with sample data and default policies

Available tables:
- users
- posts

Active RLS Policies:
- tenant_isolation on table users: tenant_id = 100
- tenant_posts on table posts: tenant_id = 100

=== Interactive SQL Mode ===
Enter SQL queries to execute with RLS applied

Special commands:
- CREATE POLICY <name> ON <table> USING (<expression>)
- SHOW POLICIES
- RESET POLICIES <table>
- exit/quit - Exit the REPL

Demo Flow:
1. Try 'SELECT * FROM users;' (note tenant_id = 100 filter applied)
2. Add a new policy: 'CREATE POLICY user_filter ON users USING (id = 1)'
3. Try 'SELECT * FROM users;' again (notice only user with id = 1 is shown)
```

And in the interactive session

```sql
sql> select * from users;

Results:
Row 1: {Some("id"): (Integer, 1), Some("username"): (Text, "alice"), Some("tenant_id"): (Integer, 100)}
Row 2: {Some("id"): (Integer, 2), Some("username"): (Text, "bob"), Some("tenant_id"): (Integer, 100)}

2 row(s) returned

sql> create policy test_policy on users using (id = 2);   
Policy created successfully (1 rows affected)

sql> select * from users;

Results:
Row 1: {Some("id"): (Integer, 2), Some("username"): (Text, "bob"), Some("tenant_id"): (Integer, 100)}

1 row(s) returned

sql> 
```


## Project Structure

```
libsql_rls/
├── src/
│   ├── lib.rs         # Library entry point
│   ├── connection.rs  # RLS connection wrapper
│   ├── policy.rs      # Policy management
│   └── error.rs       # Error handling
├── tests/
│   └── policy_tests.rs # Test for policy parsing
├── rls_repl.rs        # Database setup tool
├── test_with_rls.rs   # Interactive RLS demo
└── Cargo.toml
```

## Current Status

The project currently:
- Successfully parses and stores CREATE POLICY statements
- Has a working test suite
- Provides a foundation for implementing full RLS functionality
- Automatically initializes required metadata tables

## TODO: Production Readiness

To make this library production-ready, the following items need to be addressed:

1. **SQL Parsing Robustness**
   - Replace regex-based parsing with a complete SQL parser
   - Handle all SQL statement types properly
   - Support complex expressions in policy conditions

2. **Performance Optimization**
   - Benchmark and optimize query rewriting
   - Add caching for frequently accessed policies
   - Minimize overhead for non-RLS operations

3. **Security Hardening**
   - Ensure policies can't be bypassed through SQL injection
   - Add support for parameterized values in policy expressions
   - Implement proper escaping for all user inputs

4. **Feature Completeness**
   - Support UPDATE and DELETE statement rewriting with RLS
   - Implement full policy inheritance for views
   - Add support for row-level permissions (not just filters)
   - Implement user context/session variables

5. **Usability Improvements**
   - Add helper functions for common RLS patterns
   - Provide CLI tools for policy management
   - Create comprehensive documentation with examples

6. **Testing and Validation**
   - Add extensive unit and integration tests
   - Benchmark against large datasets
   - Test with complex queries and joins
   - Create stress tests for concurrent access

7. **Operational Features**
   - Add policy debugging and logging capabilities
   - Implement policy versioning and migration support
   - Add tools for policy analysis and conflict detection

8. **Standards Compliance**
   - Ensure compatibility with PostgreSQL RLS syntax
   - Implement standard RLS functions and operators 