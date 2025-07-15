# Project Structure

This document explains the organized structure of the basic-auth project.

## Root Directory

```
basic-auth/
├── .env -> config/env/.env     # Symbolic link to environment file
├── .gitignore                  # Git ignore rules
├── Cargo.toml                  # Rust package configuration
├── Cargo.lock                  # Dependency lock file
├── README.md                   # Project overview and setup instructions
├── PROJECT_STRUCTURE.md        # This file - project organization guide
│
├── config/                     # Configuration files
│   ├── env/                   # Environment variables
│   │   ├── .env              # Main environment file
│   │   ├── .env.example      # Example environment file
│   │   └── .env.test         # Test environment file
│   ├── diesel.toml           # Diesel ORM configuration
│   └── docker-compose.yml    # Docker compose configuration
│
├── docs/                      # Documentation
│   ├── api/                  # API documentation
│   ├── architecture/         # Architecture documentation
│   └── *.md                 # Various guide files
│
├── src/                      # Source code
│   ├── main.rs              # Application entry point
│   ├── lib.rs               # Library root
│   ├── application/         # Application layer (use cases, DTOs)
│   ├── domain/              # Domain layer (entities, services)
│   ├── infrastructure/      # Infrastructure layer (persistence, external services)
│   └── interfaces/          # Interface layer (API, CLI)
│
├── tests/                    # Test files
│   ├── unit/                # Unit tests
│   ├── integration/         # Integration tests
│   └── e2e/                 # End-to-end tests
│
├── migrations/              # Database migrations
├── scripts/                 # Utility scripts
├── deployments/            # Deployment configurations
└── target/                 # Rust build artifacts (auto-generated)
```

## Organization Principles

### 1. Configuration Management

- All configuration files are centralized in `config/`
- Environment files are organized in `config/env/`
- A symbolic link maintains `.env` in root for compatibility

### 2. Documentation

- All project documentation is in `docs/`
- API docs are separated in `docs/api/`
- Architecture documentation is in `docs/architecture/`

### 3. Clean Architecture

- Source code follows Clean Architecture principles
- Clear separation between layers: domain, application, infrastructure, interfaces

### 4. Testing

- Comprehensive test structure with unit, integration, and e2e tests
- Common test utilities in `tests/common/`

## File Locations

### Configuration Files

- **Environment Variables**: `config/env/`
    - `.env` - Main environment configuration for development
    - `.env.example` - Template file showing required environment variables
    - `.env.test` - Test-specific environment configuration
    - Symbolic link in root (`.env -> config/env/.env`) maintains compatibility
- **Database Config**: `config/diesel.toml`
    - Diesel ORM configuration for database schema management
    - Specifies schema file location and migration directory
- **Docker Config**: `config/docker-compose.yml`
    - Docker services configuration for local development
    - Includes database, Redis, and other infrastructure services

### Documentation

- **Project Guides**: `docs/*.md`
    - Architecture guides, security guidelines, and development best practices
    - Rust-specific idiomatic programming guides
    - Authentication and authorization documentation
- **API Documentation**: `docs/api/`
    - `openapi.yaml` - OpenAPI/Swagger specification for REST APIs
    - Generated API documentation and examples
- **Architecture**: `docs/architecture/`
    - System architecture diagrams and explanations
    - Design decisions and architectural patterns used
    - Clean Architecture implementation details

### Development

- **Source Code**: `src/`
    - `main.rs` - Application entry point and server setup
    - `lib.rs` - Library root exposing public modules
    - `schema.rs` - Auto-generated database schema (Diesel)
    - **Application Layer**: `src/application/`
        - `dtos/` - Data Transfer Objects for API communication
        - `ports/` - Interface definitions (traits) for external dependencies
        - `use_cases/` - Business logic implementation and orchestration
    - **Domain Layer**: `src/domain/`
        - `entities/` - Core business entities with domain logic
        - `value_objects/` - Immutable objects representing domain concepts
        - `services/` - Domain services for complex business operations
        - `repositories/` - Repository trait definitions
        - `errors/` - Domain-specific error types
    - **Infrastructure Layer**: `src/infrastructure/`
        - `persistence/` - Database implementations and models
        - `security/` - Security implementations (JWT, password hashing)
        - `config/` - Dependency injection and configuration setup
        - `external_services/` - Third-party service integrations
    - **Interface Layer**: `src/interfaces/`
        - `api/` - HTTP API controllers, routes, and middlewares
        - `cli/` - Command-line interface implementations
- **Tests**: `tests/`
    - `unit/` - Fast, isolated tests for individual components
    - `integration/` - Tests for component interactions
    - `e2e/` - End-to-end tests simulating real user scenarios
    - `common/` - Shared test utilities and helper functions
- **Database Migrations**: `migrations/`
    - Version-controlled database schema changes
    - Each migration has `up.sql` (apply) and `down.sql` (rollback)
    - Managed by Diesel CLI for safe schema evolution
- **Build Scripts**: `scripts/`
    - `setup_db.sh` - Database initialization and migration script
    - `generate_api_docs.sh` - API documentation generation
    - Development workflow automation

### Deployment & Infrastructure

- **Deployment Configurations**: `deployments/`
    - `docker/` - Container configurations for different environments
        - `dev/Dockerfile.dev` - Development container setup
        - `prod/Dockerfile.prod` - Production-optimized container
    - `kubernetes/` - Kubernetes manifests for container orchestration
        - `deployment.yaml` - K8s deployment configuration
        - Service definitions and ingress rules

## Maintenance

When adding new files:

1. **Configuration files** → `config/`
    - Environment variables go to `config/env/`
    - Service configurations (database, cache, etc.) go to `config/`
2. **Documentation** → `docs/`
    - API specs go to `docs/api/`
    - Architecture docs go to `docs/architecture/`
    - General guides stay in `docs/`
3. **Database changes** → `migrations/`
    - Always create both up and down migrations
    - Use descriptive names with timestamps
4. **Deployment configs** → `deployments/`
    - Docker files go to `deployments/docker/`
    - Kubernetes manifests go to `deployments/kubernetes/`
5. **Utility scripts** → `scripts/`
    - Make scripts executable (`chmod +x`)
    - Include usage documentation in script headers

## Development Workflow

### Clean Architecture Implementation

This project follows Clean Architecture principles with clear layer separation:

1. **Domain Layer** (Inner) - Pure business logic, no external dependencies
2. **Application Layer** - Orchestrates domain objects, defines use cases
3. **Infrastructure Layer** - Implements external concerns (database, web, etc.)
4. **Interface Layer** (Outer) - Handles external communication (HTTP, CLI)

### Dependency Rules

- Dependencies point inward (outer layers depend on inner layers)
- Domain layer has no external dependencies
- Use dependency injection for loose coupling
- Interfaces (traits) define contracts between layers

### Testing Strategy

- **Unit Tests**: Test individual functions and methods in isolation
- **Integration Tests**: Test layer interactions and data flow
- **E2E Tests**: Test complete user workflows through HTTP API
- **Test Helpers**: Shared utilities for test data setup and assertions

### Database Management

- Use Diesel migrations for schema changes
- Keep migrations small and focused
- Always test both up and down migrations
- Schema file (`src/schema.rs`) is auto-generated, don't edit manually

This structure ensures a clean, maintainable, and scalable project organization that follows Rust and Clean Architecture
best practices.
