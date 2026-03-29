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

## License and Commercial Use

This project is licensed under the **Prosperity Public License 3.0.0**.

### What does this mean for you?

- **Personal and Non-Profit Use:** You are free to use, study, and modify this software at no cost for personal,
  educational, or research purposes.
- **Commercial Use:** If you are a company or a professional using this software for profit-making activities, you are
  granted a **30-day trial period**.

### How to Obtain a Commercial License

To continue using the software for commercial purposes after the 30-day trial, you must purchase a dedicated commercial
license.

To request a quote or activate your license, please contact:
**ldcproductions@proton.me**

*Please use the subject line: "Commercial License Request - pwd-strength"*

---
*Note: This software is built using the Dioxus framework (MIT/Apache 2.0). All third-party open-source components remain
subject to their respective licenses.*