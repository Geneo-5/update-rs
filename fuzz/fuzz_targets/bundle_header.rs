//! Cible de fuzzing pour le parsing du header de bundle
//!
//! Cette cible fuzz le parsing et la validation du header de bundle.
//! Le header est configuré avec une taille par défaut de 5120 octets,
//! mais peut être adapté via le paramètre de générique constant `H`.
//! Elle vérifie que le parser ne plante pas sur des entrées malformées et que
//! toutes les validations de bornes sont correctes.

use libfuzzer_sys::fuzz_target;
use update_bundle::BundleHeader;

fuzz_target!(|data: &[u8]| {
    // Appel au parser réel : retourne Result, pas de panic
    let _ = BundleHeader::parse(data);

    // Le parser retourne une erreur propre pour :
    // - données trop courtes (< header_size)
    // - magic number incorrect
    // - padding non nul
    // Aucune condition de course ni panic n'est attendue.
});
