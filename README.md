# libSQL Row Level Security (RLS) Extension

This extension adds PostgreSQL-like Row Level Security capabilities to libSQL. It performs RLS policy application through AST manipulation rather than string manipulation, ensuring robust and reliable security enforcement.

## Current Status

> **IMPORTANT NOTE:** This project is currently at the proof-of-concept stage. The code demonstrates the architectural approach to implementing Row Level Security in libSQL through AST manipulation. Due to API changes in recent libSQL versions, the current implementation requires adaptation to work with the latest libSQL API. The code structure and approach are sound, but specific API usage needs updates.

## Features

- PostgreSQL-compatible RLS syntax
- AST-based policy enforcement
- Support for complex policy conditions
- Automatic policy application to queries

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/libsql_rls.git
cd libsql_rls

# Build the extension
cargo build --release
```

## Usage

### Interactive Mode

To launch an interactive libSQL shell with RLS support:

```bash
cargo run --bin libsql_shell -- [DATABASE_PATH]
```

Or use the compiled binary directly:

```bash
./target/release/libsql_shell [DATABASE_PATH]
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

```bash
cargo test
```

## Development

This project uses Rust and integrates with libSQL. Make sure you have:

1. Rust installed (https://rustup.rs/)
2. Cargo package manager
3. libSQL development dependencies

## Project Structure

- `src/ast.rs` - AST manipulation utilities
- `src/parser.rs` - SQL parser with RLS extensions
- `src/policy.rs` - Policy management
- `src/rewriter.rs` - SQL rewriting to apply RLS
- `src/bin/shell.rs` - Interactive shell
- `tests/` - Comprehensive test suite
- `examples/` - Example usage

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details. 