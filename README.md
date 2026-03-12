## Edge Python Infrastructure

Infrastructure deployment tool for managing Cloudflare CDN and DNS configurations.

## Features

1. **Cloudflare DNS Management**: Automated CNAME record creation with proxy support.
2. **Cloudflare CDN Management**: CDN bucket creation, file upload and cache refresh.

## Prerequisites

- Rust 2024 edition or later.
- Cloudflare API token with DNS edit permissions.

## Usage

```bash
git clone https://github.com/dylan-sutton-chavez/edge-python_infrastructure.git
cd tiny-python_infrastructure
cargo build --release
```

## Project Tree

```bash
├───.github
│   └───workflows
│       └── main.yml
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