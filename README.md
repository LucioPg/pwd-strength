# pwd-strength

Password strength evaluation library with configurable blacklist support.

## Features

| Feature | Description |
|---------|-------------|
| `async` (default) | Async evaluation with cancellation support |
| `tracing` | Logging via tracing crate |

## Environment Variables

- `PWD_BLACKLIST_PATH`: Custom path to blacklist file (default: `./assets/10k-most-common.txt`)

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
pwd-strength = { git = "https://github.com/LucioPg/pwd-strength" }
```

## Example

```rust
use pwd_strength::{init_blacklist, evaluate_password_strength};
use secrecy::SecretString;

// Initialize blacklist (call once at startup)
init_blacklist().expect("Failed to load blacklist");

// Evaluate a password
let password = SecretString::new("MyP@ssw0rd!".to_string().into());

#[cfg(feature = "async")]
let evaluation = evaluate_password_strength(&password, None);

#[cfg(not(feature = "async"))]
let evaluation = evaluate_password_strength(&password);

println!("Score: {:?}", evaluation.score);
println!("Strength: {:?}", evaluation.strength());
```

## Strength Levels

Scores map to strength levels:

| Score | Strength |
|-------|----------|
| 96+ | GOD |
| 85+ | EPIC |
| 70+ | STRONG |
| 50+ | MEDIUM |
| 0-49 | WEAK |

## License

MIT
