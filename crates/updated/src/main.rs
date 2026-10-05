//! Démon de mise à jour.
//!
//! Spécification : `docs/spec/04-update-flow.md` (en cours de rédaction).

fn main() {
    println!("updated {}", env!("CARGO_PKG_VERSION"));
}
