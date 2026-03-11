## Tiny Python Infrastructure

Infrastructure deployment tool for managing GCP services and Cloudflare DNS configurations.

## Features

**Cloudflare DNS Management**: Automated CNAME record creation with proxy support.

## Prerequisites

Rust 2024 edition or later.
Cloudflare API token with DNS edit permissions.

## Usage

```bash
git clone https://github.com/dylan-sutton-chavez/tinypy-infra.git
cd tinypy-infra
cargo build --release
```

## Project Tree

```bash
├── Cargo.toml
├── README.md
├── src
│   ├── cloudflare.rs
│   ├── config.rs
│   ├── lib.rs
│   └── main.rs
└── tests
    ├── cloudflare_test.rs
    └── integration_test.rs
```

## Testing

```bash
cargo test
```

## License

Apache License, Version 2.0
