# Basic Auth - Rust Authentication Service

[![Rust](https://img.shields.io/badge/rust-1.75.0%2B-orange.svg)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A modern, secure authentication service built with Rust, following Domain-Driven Design (DDD) and Clean Architecture
principles.

## Features

- **Secure Authentication** - JWT-based authentication with Argon2 password hashing
- **User Management** - Create, read, update, and delete user accounts
- **Role-Based Access Control** - Fine-grained permission system
- **Clean Architecture** - Separation of concerns for maintainability and testability
- **Domain-Driven Design** - Focus on the core domain and business logic
- **Fully Tested** - Comprehensive unit, integration, and end-to-end tests
- **Docker Support** - Containerized deployment ready

## Tech Stack

- **Rust** - Systems programming language that combines performance and safety
- **Actix Web** - High-performance web framework
- **Diesel** - ORM and query builder
- **PostgreSQL** - Relational database
- **JWT** - JSON Web Tokens for authentication
- **Argon2** - State-of-the-art password hashing algorithm
- **Docker** - Containerization

## Project Structure

This project follows DDD and Clean Architecture principles with a clear separation of concerns:

```
basic-auth/
├── src/
│   ├── domain/        # Core business logic
│   ├── application/   # Use cases and application services
│   ├── infrastructure/# Framework and external dependencies
│   ├── interfaces/    # API endpoints and controllers
│   └── common/        # Shared utilities
├── tests/             # Test suite
└── ...
```

For a detailed explanation of the project structure, see [FOLDER_STRUCTURE.md](FOLDER_STRUCTURE.md).

## Getting Started

### Prerequisites

- Rust (latest stable version)
- PostgreSQL
- Docker and Docker Compose (optional)

### Setup with Docker

1. Clone the repository:

```bash
git clone https://github.com/yourusername/basic-auth.git
cd basic-auth
```

2. Start the application and database:

```bash
docker-compose up -d
```

3. Access the API at http://localhost:8080

### Manual Setup

1. Clone the repository:

```bash
git clone https://github.com/yourusername/basic-auth.git
cd basic-auth
```

2. Copy example environment file and configure:

```bash
cp .env.example .env
# Edit .env with your database credentials and other settings
```

3. Set up the database:

```bash
diesel setup
diesel migration run
```

4. Run the application:

```bash
cargo run
```

5. Access the API at http://localhost:8080

## API Documentation

### Authentication Endpoints

- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Authenticate and get JWT token
- `POST /api/auth/logout` - Invalidate the current session

### User Management Endpoints

- `GET /api/users/me` - Get current user information
- `GET /api/users/{id}` - Get user by ID
- `PUT /api/users/{id}` - Update user
- `DELETE /api/users/{id}` - Delete user

For detailed API documentation, see the OpenAPI specification in the `docs/api` directory.

## Development

### Running Tests

```bash
# Unit tests
cargo test --lib

# Integration tests
cargo test --features integration_tests

# End-to-end tests
cargo test --features e2e_tests
```

### Code Formatting and Linting

```bash
# Format code
cargo fmt

# Run linter
cargo clippy
```

## Deployment

### Docker Production Deployment

```bash
# Build production image
docker build -f deployments/docker/prod/Dockerfile.prod -t basic-auth:latest .

# Run container
docker run -p 8080:8080 --env-file .env.prod basic-auth:latest
```

For more deployment options, see the [deployment documentation](deployments/README.md).

## Project Documentation

- [Architecture Overview](docs/architecture/ARCHITECTURE.md)
- [Security Guide](SECURITY_GUIDE.md)
- [Authentication Schema Guide](AUTHENTICATION_SCHEMA_GUIDE.md)
- [Idiomatic Rust Guide](IDIOMATIC_RUST_GUIDE.md)
- [Alternative Structures](ALTERNATIVE_STRUCTURES.md)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.
