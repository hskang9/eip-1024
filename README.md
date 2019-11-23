# EIP-1024 ![Crates.io](https://img.shields.io/crates/d/EIP-1024.svg) [![Released API docs](https://docs.rs/EIP-1024/badge.svg)](https://docs.rs/EIP-1024)

## Example

```rust
use eip_1024::{get_encryption};

fn main() {
	assert_eq!(
		hash_structured_data(typed_data).unwrap().to_hex::<String>(),
		"be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
	)
}

```

## License

This crate is distributed under the terms of GNU GENERAL PUBLIC LICENSE version 3.0.

See [LICENSE](../../LICENSE) for details.
