# Contributing to libSQL Row Level Security

Thank you for your interest in contributing to libSQL RLS! This document provides guidelines and instructions for contributing to this project.

## Development Setup

### Prerequisites

1. Rust - Install from [https://rustup.rs/](https://rustup.rs/)
2. Cargo - Comes with Rust installation

### Setting up the Development Environment

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/libsql_rls.git
   cd libsql_rls
   ```

2. Build the project:
   ```bash
   cargo build
   ```

3. Run tests:
   ```bash
   cargo test
   ```

## Development Workflow

1. Create a new branch for your feature or fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and ensure they are properly tested.

3. Run the test suite to ensure everything works correctly:
   ```bash
   cargo test
   ```

4. Format your code:
   ```bash
   cargo fmt
   ```

5. Run the linter to check for any issues:
   ```bash
   cargo clippy
   ```

6. Commit your changes with a clear and descriptive commit message:
   ```bash
   git commit -m "Add feature: your feature description"
   ```

7. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

8. Create a pull request.

## Pull Request Guidelines

- Provide a clear and descriptive title.
- Include a summary of what changes were made and why.
- Ensure all tests pass.
- Reference any related issues.
- Code should be well-documented, especially public APIs.

## Code Style

This project follows the Rust style guidelines. Please ensure your code is formatted with `cargo fmt` and passes `cargo clippy` checks.

## Testing

- Write tests for all new features and bug fixes.
- Ensure all existing tests continue to pass.
- Tests should be comprehensive and cover edge cases.

## Documentation

- Document all public APIs.
- Update the README.md if necessary.
- Add examples for new features.

## License

By contributing to this project, you agree that your contributions will be licensed under the project's MIT License. 