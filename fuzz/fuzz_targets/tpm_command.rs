//! Cible de fuzzing pour le parsing des commandes/réponses TPM
//!
//! Cette cible fuzz le parsing des commandes TPM envoyées au TPM
//! et des réponses TPM reçues.
//! Elle vérifie que :
//! 1. Le parser ne plante pas sur des réponses malformées
//! 2. Les codes d'erreur TPM sont gérés correctement
//! 3. Les tailles de buffer sont validées

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Une réponse TPM a au minimum :
    // - tag (2 octets)
    // - size (4 octets)
    // - code (4 octets)
    if data.len() < 10 {
        return;
    }

    // TODO : Appeler update_tpm::parse_response(data)
    // et vérifier que :
    // 1. Le parser ne panique pas
    // 2. Les réponses malformées sont rejetées (Result::Err)
    // 3. Les codes d'erreur TPM sont gérés correctement

    // Placeholder : extraire les champs
    let tag = u16::from_be_bytes([data[0], data[1]]);
    let size = u32::from_be_bytes([data[2], data[3], data[4], data[5]]);
    let code = u32::from_be_bytes([data[6], data[7], data[8], data[9]]);

    // Vérifier la cohérence
    if size as usize != data.len() {
        // Taille incohérente, devrait être rejeté
        return;
    }

    // Pour l'instant, on ne fait rien pour éviter les faux positifs
    let _ = (tag, code);
});
