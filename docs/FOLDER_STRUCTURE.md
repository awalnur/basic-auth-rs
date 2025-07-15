# Struktur Folder Proyek Autentikasi dengan Prinsip DDD dan Clean Architecture

Struktur folder berikut dirancang berdasarkan prinsip Domain-Driven Design (DDD) dan Clean Architecture untuk memudahkan
pemeliharaan dan pengembangan dengan memisahkan kode berdasarkan domain bisnis dan tanggung jawab.

```
basic-auth/
├── .env                        # File konfigurasi environment
├── .env.example                # Contoh file .env untuk panduan pengembang
├── .gitignore                  # File untuk mengabaikan file tertentu di Git
├── Cargo.toml                  # Konfigurasi proyek dan dependensi
├── Cargo.lock                  # Lock file untuk dependensi yang tepat
├── diesel.toml                 # Konfigurasi Diesel ORM
├── README.md                   # Dokumentasi proyek utama
├── Dockerfile                  # Konfigurasi untuk build Docker image
├── docker-compose.yml          # Konfigurasi untuk orkestrasi multi-container
├── .dockerignore               # File untuk mengabaikan file saat Docker build
│
├── deployments/                # Konfigurasi deployment
│   ├── docker/                 # Docker configuration tambahan
│   │   ├── dev/                # Konfigurasi untuk development
│   │   │   ├── Dockerfile.dev  # Dockerfile untuk development
│   │   │   └── docker-compose.dev.yml
│   │   └── prod/               # Konfigurasi untuk production
│   │       ├── Dockerfile.prod # Dockerfile untuk production
│   │       └── docker-compose.prod.yml
│   └── kubernetes/             # Konfigurasi Kubernetes (jika diperlukan)
│       ├── deployment.yaml
│       └── service.yaml
│
├── docs/                       # Dokumentasi teknis dan panduan
│   ├── api/                    # Dokumentasi API (OpenAPI/Swagger)
│   │   └── openapi.yaml        # Spesifikasi OpenAPI
│   ├── guides/                 # Panduan pengembangan dan penggunaan
│   │   ├── AUTHENTICATION_SCHEMA_GUIDE.md
│   │   ├── SECURITY_GUIDE.md
│   │   └── IDIOMATIC_RUST_GUIDE.md
│   ├── diagrams/               # Diagram sistem dan arsitektur
│   │   ├── architecture.png    # Diagram arsitektur sistem
│   │   ├── domain_model.png    # Diagram model domain
│   │   └── use_cases.png       # Diagram use case
│   └── adr/                    # Architecture Decision Records
│       └── 001-hexagonal-architecture.md
│
├── migrations/                 # Migrasi database Diesel
│   ├── 00000000000000_diesel_initial_setup/
│   ├── 2025-06-27-065731_create_users/
│   └── 2025-07-01-090351_create_complex_auth_schema/
│
├── scripts/                    # Script utilitas dan otomasi
│   ├── setup_db.sh             # Script untuk setup database
│   └── generate_api_docs.sh    # Script untuk generate dokumentasi API
│
├── src/                        # Kode sumber utama
│   ├── main.rs                 # Entry point aplikasi
│   │
│   ├── domain/                 # Domain Layer (Core Business Logic)
│   │   ├── mod.rs
│   │   ├── entities/           # Domain entities (tidak bergantung pada infrastruktur)
│   │   │   ├── mod.rs
│   │   │   ├── user.rs         # Entity User
│   │   │   ├── role.rs         # Entity Role
│   │   │   ├── permission.rs   # Entity Permission
│   │   │   └── session.rs      # Entity Session
│   │   │
│   │   ├── value_objects/      # Value objects
│   │   │   ├── mod.rs
│   │   │   ├── email.rs        # Value object Email
│   │   │   ├── password.rs     # Value object Password
│   │   │   └── token.rs        # Value object Token
│   │   │
│   │   ├── aggregates/         # Aggregate roots
│   │   │   ├── mod.rs
│   │   │   └── user_aggregate.rs # User aggregate root
│   │   │
│   │   ├── repositories/       # Repository interfaces
│   │   │   ├── mod.rs
│   │   │   ├── user_repository.rs
│   │   │   └── role_repository.rs
│   │   │
│   │   ├── services/           # Domain services
│   │   │   ├── mod.rs
│   │   │   ├── authentication_service.rs
│   │   │   └── authorization_service.rs
│   │   │
│   │   └── errors/             # Domain specific errors
│   │       ├── mod.rs
│   │       └── domain_error.rs
│   │
│   ├── application/            # Application Layer (Use Cases)
│   │   ├── mod.rs
│   │   ├── dtos/               # Data Transfer Objects
│   │   │   ├── mod.rs
│   │   │   ├── user_dto.rs
│   │   │   └── auth_dto.rs
│   │   │
│   │   ├── use_cases/          # Use cases / Interactors
│   │   │   ├── mod.rs
│   │   │   ├── auth/
│   │   │   │   ├── mod.rs
│   │   │   │   ├── login_use_case.rs
│   │   │   │   ├── logout_use_case.rs
│   │   │   │   └── refresh_token_use_case.rs
│   │   │   └── user/
│   │   │       ├── mod.rs
│   │   │       ├── create_user_use_case.rs
│   │   │       ├── update_user_use_case.rs
│   │   │       └── get_user_use_case.rs
│   │   │
│   │   ├── ports/              # Ports (interfaces to infrastructure)
│   │   │   ├── mod.rs
│   │   │   ├── auth_port.rs    # Authentication port
│   │   │   └── storage_port.rs # Storage port
│   │   │
│   │   └── services/           # Application services
│   │       ├── mod.rs
│   │       └── token_service.rs
│   │
│   ├── infrastructure/         # Infrastructure Layer (External Interfaces)
│   │   ├── mod.rs
│   │   ├── config/             # Configuration
│   │   │   ├── mod.rs
│   │   │   ├── app_config.rs
│   │   │   └── database.rs
│   │   │
│   │   ├── persistence/        # Database implementations
│   │   │   ├── mod.rs
│   │   │   ├── models/         # Database models
│   │   │   │   ├── mod.rs
│   │   │   │   ├── user_model.rs
│   │   │   │   └── role_model.rs
│   │   │   ├── repositories/   # Repository implementations
│   │   │   │   ├── mod.rs
│   │   │   │   ├── user_repository_impl.rs
│   │   │   │   └── role_repository_impl.rs
│   │   │   └── schema.rs       # Diesel schema
│   │   │
│   │   ├── security/           # Security implementations
│   │   │   ├── mod.rs
│   │   │   ├── password_hasher.rs
│   │   │   └── jwt_provider.rs
│   │   │
│   │   └── external_services/  # Integrasi dengan layanan eksternal
│   │       ├── mod.rs
│   │       └── email_service.rs
│   │
│   ├── interfaces/             # Interface Layer (API, CLI, etc.)
│   │   ├── mod.rs
│   │   ├── api/                # API interfaces
│   │   │   ├── mod.rs
│   │   │   ├── routes.rs       # Route definitions
│   │   │   ├── middlewares/    # HTTP middlewares
│   │   │   │   ├── mod.rs
│   │   │   │   ├── auth_middleware.rs
│   │   │   │   └── logging_middleware.rs
│   │   │   │
│   │   │   └── controllers/    # Controllers for API endpoints
│   │   │       ├── mod.rs
│   │   │       ├── auth_controller.rs
│   │   │       └── user_controller.rs
│   │   │
│   │   └── cli/                # Command line interfaces
│   │       ├── mod.rs
│   │       └── commands.rs
│   │
│   └── common/                 # Shared utilities and helpers
│       ├── mod.rs
│       ├── errors/             # Common error types
│       │   ├── mod.rs
│       │   └── app_error.rs
│       ├── logging/            # Logging utilities
│       │   ├── mod.rs
│       │   └── logger.rs
│       └── utils/              # Utility functions
│           ├── mod.rs
│           └── validation.rs
│
├── tests/                      # Pengujian
│   ├── common/                 # Kode pengujian yang dapat digunakan kembali
│   │   ├── mod.rs
│   │   └── test_helpers.rs
│   │
│   ├── unit/                   # Pengujian unit
│   │   ├── domain/             # Domain layer tests
│   │   │   ├── entities_tests.rs
│   │   │   └── services_tests.rs
│   │   ├── application/        # Application layer tests
│   │   │   └── use_cases_tests.rs
│   │   └── infrastructure/     # Infrastructure layer tests
│   │       └── repositories_tests.rs
│   │
│   ├── integration/            # Pengujian integrasi
│   │   ├── api_tests.rs
│   │   └── repository_tests.rs
│   │
│   └── e2e/                    # End-to-end tests
│       └── auth_flow_tests.rs
│
└── examples/                   # Contoh penggunaan
    ├── basic_auth_flow.rs
    └── role_based_access.rs
```

## Penjelasan Struktur dengan Prinsip DDD dan Clean Architecture

### 1. Domain Layer (Core)

Domain layer adalah inti aplikasi yang berisi aturan bisnis dan entitas. Layer ini sepenuhnya independen dari framework
dan infrastruktur eksternal.

- **entities/**: Domain entities yang merepresentasikan konsep inti dalam domain bisnis
- **value_objects/**: Objek tanpa identitas yang digunakan untuk menggambarkan aspek dari entitas
- **aggregates/**: Kelompok entitas yang diakses melalui aggregate root
- **repositories/**: Interface untuk akses data entitas (tanpa implementasi)
- **services/**: Domain services yang berisi logika bisnis kompleks yang tidak cocok di entity tunggal
- **errors/**: Error khusus domain

### 2. Application Layer (Use Cases)

Application layer mengimplementasikan use cases sistem, mengkoordinasikan aliran data ke dan dari entitas, dan
mengarahkan entitas untuk menggunakan domain business rules untuk mencapai tujuan use case.

- **dtos/**: Data Transfer Objects untuk komunikasi antar layer
- **use_cases/**: Implementasi use cases spesifik
- **ports/**: Interface untuk berkomunikasi dengan infrastruktur eksternal
- **services/**: Services aplikasi yang mengkoordinasikan logika domain untuk use cases

### 3. Infrastructure Layer (Adapters)

Infrastructure layer berisi semua implementasi konkrit dari interface yang didefinisikan dalam application layer,
termasuk implementasi database, layanan eksternal, dan framework.

- **persistence/**: Implementasi database dan repositories
- **security/**: Implementasi mekanisme keamanan
- **external_services/**: Integrasi dengan layanan eksternal
- **config/**: Konfigurasi aplikasi dan infrastruktur

### 4. Interface Layer

Interface layer menangani bagaimana pengguna atau sistem eksternal berinteraksi dengan aplikasi.

- **api/**: REST API dan endpoint
- **cli/**: Command Line Interface

### 5. Common

Berisi kode umum yang digunakan di seluruh aplikasi.

- **errors/**: Error handling
- **logging/**: Logging utilities
- **utils/**: Fungsi dan utilitas umum

## Keuntungan Penerapan DDD dan Clean Architecture

1. **Pemisahan Concerns**: Setiap layer memiliki tanggung jawab tertentu
2. **Testability**: Domain dan application layer mudah diuji karena tidak bergantung pada infrastruktur
3. **Flexibility**: Mudah untuk mengganti implementasi infrastruktur tanpa mengubah domain
4. **Maintainability**: Kode lebih terstruktur dan mudah dipahami
5. **Scalability**: Memudahkan pengembangan fitur baru dan perubahan

## Dependensi antar Layer

Dependensi hanya boleh mengarah ke dalam, dari layer luar ke layer dalam:

```
Interface → Application → Domain ← Infrastructure
```

Layer dalam tidak boleh bergantung pada layer luar. Infrastructure layer bergantung pada Domain layer melalui Dependency
Inversion (implementasi interface).
