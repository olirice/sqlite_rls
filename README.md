# LibSQL Row Level Security (RLS) Wrapper

This project provides a row-level security implementation for LibSQL, inspired by Postgres RLS.

## Features

- Create and manage security policies
- Parse `CREATE POLICY` statements
- Store policies in a dedicated RLS metadata table
- Intercept SQL statements to apply RLS rules

## Implementation Details

The implementation consists of several components:

1. **RlsConnection**: A wrapper around the LibSQL connection that intercepts SQL statements
2. **Policy Manager**: Handles the creation and management of security policies
3. **SQL Parsing**: Basic regex-based parsing for CREATE POLICY statements

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
└── Cargo.toml
```

## Current Status

The project currently:
- Successfully parses and stores CREATE POLICY statements
- Has a working test suite
- Provides a foundation for implementing full RLS functionality

## Future Work

- Implement query rewriting for SELECT statements to enforce RLS
- Add support for more complex policy expressions
- Enhance the policy management system
- Add more comprehensive tests 