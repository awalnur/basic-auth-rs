# Arsitektur Aplikasi Basic Auth

Dokumen ini menjelaskan arsitektur aplikasi Basic Auth yang mengimplementasikan pendekatan Domain-Driven Design (DDD)
dan Clean Architecture.

## Prinsip Arsitektur

Aplikasi ini dirancang berdasarkan prinsip-prinsip berikut:

1. **Separation of Concerns** - Memisahkan tanggung jawab ke dalam layer yang berbeda
2. **Dependency Rule** - Dependensi hanya mengarah ke dalam (inner layers)
3. **Domain-Centric** - Domain model adalah inti dari aplikasi
4. **Testability** - Arsitektur mendukung pengujian unit dan integrasi dengan mudah

## Struktur Layer

Aplikasi terdiri dari empat layer utama:

### 1. Domain Layer

Layer ini adalah inti dari aplikasi dan berisi logika bisnis utama. Layer ini tidak bergantung pada layer lain dan tidak
mengetahui detail implementasi dari layer luar.

Komponen utama:

- **Entities** - Objek domain dengan identitas dan behavior (User, Role, Permission)
- **Value Objects** - Objek domain tanpa identitas (Email, Password)
- **Repositories (Interfaces)** - Kontrak untuk akses data
- **Domain Services** - Logika bisnis yang melibatkan beberapa entity
- **Domain Events** - Event domain untuk komunikasi

### 2. Application Layer

Layer ini mengimplementasikan use cases aplikasi dengan menggunakan domain layer. Layer ini mengoordinasikan flow data
dan operasi tanpa implementasi detail.

Komponen utama:

- **Use Cases** - Implementasi kasus penggunaan aplikasi (Login, Register)
- **DTOs** - Data Transfer Objects untuk komunikasi antar layer
- **Ports** - Interface untuk infrastruktur (TokenService, EmailService)
- **Application Services** - Orkestrasi domain services dan repositories

### 3. Infrastructure Layer

Layer ini berisi implementasi teknis dari interface yang didefinisikan di domain dan application layer.

Komponen utama:

- **Repositories (Implementations)** - Implementasi database spesifik
- **Security** - Implementasi JWT, password hashing
- **External Services** - Integrasi dengan layanan eksternal
- **Persistence** - ORM, mapping entity-database

### 4. Interface Layer

Layer terluar yang berinteraksi dengan dunia luar seperti API, CLI, atau UI.

Komponen utama:

- **Controllers** - Menangani HTTP requests
- **Presenters** - Format data untuk response
- **Middlewares** - Komponen untuk request processing (auth, logging)
- **Routes** - Definisi endpoint API

## Aliran Data

Aliran data dalam aplikasi mengikuti pola berikut:

1. **Request** → Interface Layer (Controller)
2. Controller → Application Layer (Use Case)
3. Use Case → Domain Layer (Entities, Services)
4. Domain Layer ↔ Infrastructure Layer (Repository) untuk akses data
5. Hasil kembali melalui use case dan controller
6. Controller → **Response**

## Dependency Injection

Aplikasi menggunakan dependency injection manual untuk mengikat layer-layer:

```rust
// Contoh di main.rs
let user_repository = Arc::new(UserRepositoryImpl::new(pool_arc.clone()));
let auth_service = Arc::new(AuthenticationService::new(user_repository.clone()));
let login_use_case = Arc::new(LoginUseCase::new(
    auth_service.clone(), 
    token_service.clone()
));
```

## Diagram Arsitektur

```
┌─────────────────────────────────────────────────────────────┐
│ Interface Layer                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │ Controllers │  │ Middlewares │  │   Routes    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Application Layer                                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  Use Cases  │  │    DTOs     │  │    Ports    │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Domain Layer                                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │  Entities   │  │Value Objects│  │  Services   │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
│  ┌─────────────┐                                            │
│  │Repositories │                                            │
│  │ (interfaces)│                                            │
│  └─────────────┘                                            │
└───────────────────────────┬─────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Infrastructure Layer                                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐          │
│  │Repositories │  │  Security   │  │ Persistence │          │
│  │   (impl)    │  │             │  │             │          │
│  └─────────────┘  └─────────────┘  └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

## Keuntungan Arsitektur Ini

1. **Maintainability** - Perubahan pada satu layer tidak mempengaruhi layer lain
2. **Testability** - Domain dan application layer mudah diuji tanpa database atau API
3. **Flexibility** - Infrastruktur dapat diganti tanpa mengubah logika bisnis
4. **Scalability** - Komponen dapat diskalakan secara independen

## Panduan Implementasi

Saat mengimplementasikan fitur baru, ikuti pendekatan "inside-out":

1. Mulai dengan **Domain Layer** - Buat entitas, value object, dan service domain
2. Lanjutkan ke **Application Layer** - Implementasikan use case
3. Implementasikan **Infrastructure Layer** - Repository, security, dll.
4. Terakhir, buat **Interface Layer** - Controller, routes, dll.

## Contoh Flow Implementasi

Berikut adalah contoh flow implementasi untuk fitur login:

1. **Domain Layer**: `AuthenticationService` dengan method `authenticate`
2. **Application Layer**: `LoginUseCase` yang menggunakan authentication service
3. **Infrastructure Layer**: `JwtProvider` untuk implementasi token
4. **Interface Layer**: `AuthController` dengan method `login`

Dengan mengikuti arsitektur ini, Anda akan mendapatkan aplikasi yang modular, testable, dan mudah dimaintain.
