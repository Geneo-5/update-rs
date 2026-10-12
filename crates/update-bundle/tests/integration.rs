//! Tests d'intégration pour `update-bundle`.
//!
//! Ces tests construisent des bundles complets (header + chunks chiffrés)
//! et vérifient les opérations de bout en bout : déchiffrement,
//! validation de hash, itération sur les chunks.

use update_bundle::crypto::{
    aes_gcm_siv_encrypt, aes_key_wrap_padded, decrypt_manifest_key,
    derive_chunk_key,
};
use update_bundle::errors::{BundleError, CryptoError, ParseError};

fn build_header_bytes() -> [u8; 5120] {
    let mut h = [0u8; 5120];
    h[0..4].copy_from_slice(b"UPRS");
    let v: [u8; 2] = u16::to_le_bytes(1);
    h[4..6].copy_from_slice(&v);
    h[6..8].copy_from_slice(&v);
    let v2: [u8; 4] = u32::to_be_bytes(5120);
    h[8..12].copy_from_slice(&v2);
    // [12..16] min_firmware_version (0)
    h[12..16].copy_from_slice(&[0u8; 4]);
    // [16..20] bundle_version (0)
    h[16..20].copy_from_slice(&[0u8; 4]);
    let v3: [u8; 4] = u32::to_le_bytes(65536);
    h[20..24].copy_from_slice(&v3);
    let v4: [u8; 4] = u32::to_le_bytes(1);
    h[24..28].copy_from_slice(&v4);
    h[28..60].copy_from_slice(&[0x11u8; 32]);
    h[60..92].copy_from_slice(&[0x22u8; 32]);
    h[92..94].copy_from_slice(&[0x33u8; 2]);
    h[96..128].copy_from_slice(&[0x44u8; 32]);
    h[128..160].copy_from_slice(&[0x11u8; 32]);
    h[160..208].copy_from_slice(&[0x55u8; 48]);
    h[208..240].copy_from_slice(&[0x66u8; 32]);
    h[240..272].copy_from_slice(&[0x77u8; 32]);
    h[272..336].copy_from_slice(&[0x88u8; 64]);
    h[336..4963].copy_from_slice(&[0x99u8; 4627]);
    h[4963..5027].copy_from_slice(&[0xaa_u8; 64]);
    h[5027..5059].copy_from_slice(&[0xbb_u8; 32]);
    h
}

fn sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(data).into()
}

fn write_chunk(
    data: &mut Vec<u8>,
    chunk_index: u32,
    plaintext: &[u8],
    session_key: &[u8; 32],
    bundle_id: &[u8; 32],
) {
    let (chunk_key, chunk_nonce) = derive_chunk_key(session_key, bundle_id, chunk_index);
    let encrypted = aes_gcm_siv_encrypt(&chunk_key, &chunk_nonce, plaintext, b"").expect("encrypt");
    let mut chunk_data = Vec::new();
    chunk_data.extend_from_slice(&chunk_index.to_le_bytes());
    let len: [u8; 4] = u32::to_le_bytes(encrypted.len() as u32);
    chunk_data.extend_from_slice(&len);
    chunk_data.extend_from_slice(&[0u8; 32]);
    chunk_data.extend_from_slice(&encrypted);
    data.extend_from_slice(&chunk_data);
}

/// Test d'intégration : un bundle complet avec un chunk,
/// passé à BundleReader, déchiffré, et validé.
#[test]
fn full_bundle_roundtrip() {
    let mut header = build_header_bytes();
    let session_key: [u8; 32] = [0x88u8; 32];
    let bundle_id: [u8; 32] = [0x11u8; 32];
    let chunk_count = 1u32;

    // Construire un chunk de données
    let plaintext = b"hello from the full bundle test";
    let mut data = Vec::from(&header[..5120]);

    // Encodage du manifeste : 64 octets de données arbitraires chiffrées
    let (manifest_key, manifest_nonce) = decrypt_manifest_key(&session_key, &bundle_id);
    let manifest_cbor = [0x12u8; 64];
    let encrypted_manifest =
        aes_gcm_siv_encrypt(&manifest_key, &manifest_nonce, &manifest_cbor, b"").expect("encrypt");
    data.extend_from_slice(&encrypted_manifest);

    // Ajouter le chunk
    write_chunk(&mut data, 0, plaintext, &session_key, &bundle_id);

    // Calculer le hash du bundle (tout après le header)
    let bundle_hash = sha256(&data[5120..]);
    header[128..160].copy_from_slice(&bundle_hash);

    // Calculer le hash du manifeste (tout après le header, avant les chunks)
    let manifest_hash = sha256(&encrypted_manifest);
    header[96..128].copy_from_slice(&manifest_hash);

    let v7: [u8; 4] = u32::to_le_bytes(chunk_count);
    header[24..28].copy_from_slice(&v7);

    data[..5120].copy_from_slice(&header);

    let reader = update_bundle::reader::BundleReader::new(&data).expect("new");

    // Validation
    assert!(reader.validate_bundle_hash().is_ok());
    assert!(reader.validate_manifest_hash().is_ok());

    // Récupération de la clé de session via wrap
    let wrapped = aes_key_wrap_padded(&session_key, &[0x22u8; 32]).expect("wrap");
    let wrapped_bytes: [u8; 40] = wrapped.try_into().expect("clé enveloppée de 40 octets");
    let kek_hash = sha256(&[0x22u8; 32]);
    header[60..92].copy_from_slice(&kek_hash);
    header[4963..5003].copy_from_slice(&wrapped_bytes);
    let mut data_with_kek = data;
    data_with_kek[..5120].copy_from_slice(&header);

    let reader = update_bundle::reader::BundleReader::new(&data_with_kek).expect("new");
    let session = reader
        .decrypt_session_key(&[0x22u8; 32])
        .expect("decrypt_session_key");

    // Lecture du chunk
    let chunk = reader
        .read_chunk(0, &session, &bundle_id, chunk_count, true)
        .expect("read_chunk");
    assert_eq!(chunk.encrypted_data.as_ref(), plaintext);
}

/// 5 chunks de tailles différentes (1 KiB à 128 KiB), tous déchiffrés.
#[test]
fn multi_chunk_different_sizes() {
    let mut header = build_header_bytes();
    let max_chunk: [u8; 4] = u32::to_le_bytes(u32::MAX); // chunk_size large
    header[20..24].copy_from_slice(&max_chunk);
    let fc: [u8; 4] = u32::to_le_bytes(5); // 5 chunks
    header[24..28].copy_from_slice(&fc);
    header[96..128].copy_from_slice(&[0u8; 32]); // manifest_hash placeholder

    let session_key: [u8; 32] = [0x88u8; 32];
    let bundle_id: [u8; 32] = [0x11u8; 32];

    let sizes = [1024usize, 4096, 32768, 65536, 131072];
    let mut data = Vec::from(&header[..5120]);

    for (i, &size) in sizes.iter().enumerate() {
        let plaintext: Vec<u8> = (0..size).map(|j| (j % 256) as u8).collect();
        write_chunk(&mut data, i as u32, &plaintext, &session_key, &bundle_id);
    }

    // Header avec les bons hashes
    let bundle_hash = sha256(&data[5120..]);
    header[128..160].copy_from_slice(&bundle_hash);

    // Wrap KEK pour decrypt_session_key
    let wrapped = aes_key_wrap_padded(&session_key, &[0x22u8; 32]).expect("wrap");
    header[60..92].copy_from_slice(&sha256(&[0x22u8; 32]));
    let wrapped_bytes: [u8; 40] = wrapped.try_into().expect("clé enveloppée de 40 octets");
    header[4963..5003].copy_from_slice(&wrapped_bytes);

    data[..5120].copy_from_slice(&header);

    let reader = update_bundle::reader::BundleReader::new(&data).expect("new");
    let session = reader
        .decrypt_session_key(&[0x22u8; 32])
        .expect("decrypt_session_key");

    for (i, &size) in sizes.iter().enumerate() {
        let chunk = reader
            .read_chunk(i as u32, &session, &bundle_id, 5, i == 4)
            .expect(&format!("chunk {i}"));
        assert_eq!(
            chunk.encrypted_data.len(),
            size,
            "chunk {} size mismatch",
            i
        );
    }
}

/// Conversion des erreurs ParseError → BundleError via From.
#[test]
fn error_propagation() {
    let parse: ParseError = ParseError::InvalidMagic {
        got: 0xDEADBEEF,
        expected: 0x55505253,
    };
    let bundle: BundleError = parse.into();
    match bundle {
        BundleError::Parse(ParseError::InvalidMagic { got, expected }) => {
            assert_eq!(got, 0xDEADBEEF);
            assert_eq!(expected, 0x55505253);
        }
        _ => panic!("attendu InvalidMagic"),
    }

    let crypto: CryptoError = CryptoError::InvalidKeySize {
        size: 16,
        expected: 32,
    };
    let bundle: BundleError = crypto.into();
    match bundle {
        BundleError::Crypto(CryptoError::InvalidKeySize { size, .. }) => {
            assert_eq!(size, 16);
        }
        _ => panic!("attendu InvalidKeySize"),
    }
}
