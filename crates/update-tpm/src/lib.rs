//! Abstraction du TPM 2.0.
//!
//! Spécification : `docs/spec/03-tpm.md` (en cours de rédaction).
//!
//! Le backend matériel (`tss-esapi`) et un backend logiciel réservé aux tests
//! (`swtpm` ou simulation) seront ajoutés derrière une même interface une fois
//! la spécification stabilisée.
