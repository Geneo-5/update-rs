# 02 — Format d'archive (bundle)

Statut : Brouillon

Un format dédié est retenu (voir [ADR-0001](../adr/0001-custom-bundle-format.md)).

## Exigences

- **REQ-BUN-1** — Le bundle est créé offline (`bundle-tool`) ; le temps de création n'est pas contraint.
- **REQ-BUN-2** — Le bundle DOIT pouvoir être consommé en **streaming** à la récupération :
  le device ne DOIT pas avoir à stocker l'archive entière avant de commencer à la traiter.
- **REQ-BUN-3** — Aucune donnée ne DOIT être écrite sur un slot, décompressée ou interprétée
  avant d'avoir été authentifiée.
- **REQ-BUN-4** — Le lecteur DOIT détecter troncature, réordonnancement, duplication et
  mélange de morceaux provenant de bundles différents.
- **REQ-BUN-5** — Le lecteur DOIT fonctionner à mémoire bornée (indépendante de la taille du bundle).
- **REQ-BUN-6** — Le parseur DOIT être robuste face à des entrées hostiles (limites de taille,
  pas d'allocation pilotée par une valeur non authentifiée), et fuzzé.

## Structure

```
[ en-tête (header) ][ manifeste chiffré ][ chunk 0 ][ chunk 1 ] … [ chunk N (final) ]
```

L'en-tête a une **taille fixe** (padding éventuel) pour permettre un traitement en streaming sans prélecture coûteuse.

### Composition de l'en-tête (Header)

L'en-tête contient toutes les métadonnées nécessaires au traitement en streaming et à la vérification initiale. Tous ses champs, à l'exception de la signature et du padding, sont couverts par une signature ECC (ECDSA P-256 sur `SHA-256(header[0..216])`). Le padding n'est pas signé : le lecteur DOIT vérifier qu'il est entièrement à zéro.

#### Structure binaire (esquisse, taille fixe 512 octets)

| Offset | Taille | Champ | Description |
|---|---|---|---|
| 0 | 4 | `magic` | `0x55505253` (`"UPRS"`) |
| 4 | 2 | `header_version` | Version du format de header (ex: `0x0001`). Si une future version nécessite un header plus grand, elle aura un `header_version` différent et une taille différente. |
| 6 | 2 | `alg_suite` | Suite algorithmique (ex: `0x0001` = AES-256-GCM-SIV + ECDSA P-256 + SHA-256) |
| 8 | 4 | `header_size` | Taille totale du header (constante par version, ex: 512 pour v1) |
| 12 | 4 | `min_firmware_version` | Version firmware minimale requise (anti-rollback, vérifié contre compteur NV TPM) |
| 16 | 4 | `bundle_version` | Version de ce bundle (monotone, incrémentée par l'éditeur) |
| 20 | 4 | `chunk_size` | Taille nominale d'un chunk (ex: 64 KiB) |
| 24 | 4 | `chunk_count` | Nombre total de chunks |
| 28 | 32 | `manifest_hash` | SHA-256 du manifeste signé |
| 60 | 32 | `tree_root` | Racine de l'arbre de hachage (si applicable) |
| 92 | 4 | `keywrap_alg` | `0x0001` = AES Key Wrap with Padding RFC 5649 |
| 96 | 32 | `kek_id` | Identifiant (hash) de la KEK cible dans le TPM |
| 128 | 32 | `bundle_id` | Identifiant unique du bundle (UUID ou hash) |
| 160 | 56 | `wrapped_session_key` | **AES Key Wrap (RFC 5649)** de la clé de session (Key 256-bit + IV 96-bit = 44 octets plaintext → 56 octets ciphertext) |
| 216 | 32 | `ecc_signature_r` | Composante r de la signature ECDSA P-256 (32 octets) |
| 248 | 32 | `ecc_signature_s` | Composante s de la signature ECDSA P-256 (32 octets) |
| 280 | 232 | `padding` | Réservé, mis à zéro |

**Total : 512 octets** (alignement sur secteur flash)

**Note sur `wrapped_session_key`** : La clé de session = Key (32 octets) + IV (12 octets) = **44 octets**. RFC 5649 encapsule en blocs de 8 octets : 44 octets → 48 octets (padding) + 8 octets (header RFC 5649) = **56 octets** de ciphertext.

**Note sur l'évolution du header** : si une future version nécessite un header plus grand (ex: 1024 octets), elle aura :
- Un `header_version` différent (ex: `0x0002`)
- Un `header_size` différent (ex: 1024)
- Le lecteur DOIT vérifier que `header_version` est supporté avant de lire les champs suivants

#### Détail des champs sensibles

- **Clé de session chiffrée** (`wrapped_session_key`, 56 octets) :
  - Une clé de session éphémère **AES-256-GCM-SIV** (Key 256-bit + IV 96-bit) est générée côté éditeur pour chaque bundle.
  - Cette clé (44 octets : Key + IV) est encapsulée avec **AES Key Wrap with Padding (RFC 5649)** par la KEK du dispositif cible.
  - Le résultat (56 octets de ciphertext) est placé dans le header.
  - La KEK (Key Encryption Key) réside de manière non exportable dans le TPM du dispositif cible (voir `03-tpm.md`) et **ne quitte jamais le TPM**. Le TPM effectue le déchiffrement AES Keywrap en interne et retourne uniquement la clé de session déballée (44 octets) via une session chiffrée.

- **Signature ECC** (`ecc_signature_r` + `ecc_signature_s`) :
  - Signature ECDSA P-256 calculée sur `SHA-256(header[0..216])` (tous les champs sauf signature et padding).
  - La clé publique de vérification est stockée dans le TPM (publique uniquement).

### Flux de validation

1. **Extraction** : Le lecteur lit les 512 premiers octets du bundle (le header).
2. **Vérification de magic/version** : Rejet immédiat si magic ou `header_version` invalide.
3. **Vérification de taille** : `header_size` doit correspondre à la taille attendue pour cette version.
4. **Vérification anti-rollback (version)** : `bundle_version` doit être > dernière version installée (stockée dans un index NV TPM ou fichier persistant).
5. **Vérification anti-rollback (firmware)** : `min_firmware_version` doit être ≤ version firmware actuelle du device.
6. **Hash du header (par le TPM)** : Le lecteur transmet le buffer du header au TPM via `TPM2_HashSequenceStart` + `SequenceUpdate` + `SequenceComplete` (mode PCR process). Le TPM calcule lui-même `SHA-256(header[0..216])`.
7. **Vérification de signature ECC** : Le TPM vérifie la signature ECDSA via `TPM2_VerifySignature` sur le hash qu'il a calculé (sous session chiffrée).
8. **Déchiffrement de la clé de session** : Le TPM satisfait la policy de la KEK et déchiffre `wrapped_session_key` (sous session chiffrée). Voir `03-tpm.md` pour le détail du mécanisme (AES Keywrap natif ou mécanisme alternatif x3 avec policies restreintes).
9. **Streaming** : Une fois la clé de session obtenue, le lecteur peut déchiffrer et authentifier les chunks en streaming (AEAD).

### Exigences supplémentaires

- **REQ-BUN-7** — La taille du header DOIT être fixe et connue à l'avance (pas de longueur variable). Si une future version nécessite un header plus grand, elle aura un `header_version` différent.
- **REQ-BUN-8** — Le header DOIT être aligné sur un multiple de secteur flash (512 octets ou plus).
- **REQ-BUN-9** — Le `kek_id` dans le header DOIT correspondre à l'identifiant d'une KEK provisionnée dans le TPM cible.
- **REQ-BUN-10** — L'anti-rollback DOIT vérifier à la fois `bundle_version` (contre un compteur stocké) et `min_firmware_version` (contre la version firmware actuelle).
- **REQ-BUN-11** — Le hash du header DOIT être calculé par le TPM lui-même (via `TPM2_HashSequenceStart`), jamais par le logiciel.


### Manifeste (contenu après le header)

Le manifeste est un document structuré (CBOR) chiffré et authentifié par la clé de
session AES-GCM. Il contient :

- **Métadonnées du bundle** : version, éditeur, date, description.
- **Liste des artefacts** : fichiers/images contenus dans le payload (nom, taille, hash, rôle).
- **`JailManifest`** : description complète de l'environnement d'exécution du payload
  (namespaces, `fsset`, entrypoint, capabilities, seccomp). Voir
  [06-jail.md](06-jail.md) pour le schéma détaillé.
- **Signatures internes** (optionnel) : signatures individuelles d'artefacts critiques.

Le `JailManifest` est **authentifié** par l'AEAD des chunks et **confidentiel** grâce au
chiffrement par clé de session. Il ne peut donc pas être modifié sans invalider le bundle.

## Authentification des chunks (décision)

**Décision retenue** : Chaîne AEAD par chunk avec AAD (Additional Authenticated Data) structurée.

### Mécanisme

Chaque chunk est chiffré/authentifié individuellement avec **AES-256-GCM-SIV** (RFC 8452) :

```
Plaintext:    chunk_data (taille variable, ≤ chunk_size)
Key:          session_key[0..32] (32 octets)
Nonce:        dérivé par HKDF-SHA256 de (session_key, bundle_id, chunk_index) — voir ci-dessous
AAD:          bundle_id || chunk_index || chunk_count || is_last_chunk || chunk_data_length
Ciphertext:   encrypted_chunk || auth_tag (16 octets)
```

### Dérivation du nonce

```
nonce = HKDF-SHA256(
  ikm = session_key[0..32],
  salt = bundle_id,
  info = "chunk-nonce" || chunk_index (u32 BE)
)[0..12]  // 96 bits pour AES-GCM-SIV
```

### Construction de l'AAD

```
AAD = bundle_id (32 octets) ||
      chunk_index (u32 BE, 4 octets) ||
      chunk_count (u32 BE, 4 octets) ||
      is_last_chunk (u8, 1 octet : 0x01 si dernier, 0x00 sinon) ||
      chunk_data_length (u32 BE, 4 octets)
```

### Propriétés de sécurité garanties

- **Intégrité** : toute modification d'un chunk est détectée (auth tag 128-bit).
- **Non-réordonnancement** : `chunk_index` dans l'AAD empêche de déplacer un chunk.
- **Non-troncature** : `is_last_chunk` + `chunk_count` empêche de couper le bundle.
- **Non-mix-and-match** : `bundle_id` dans l'AAD empêche de combiner des chunks de bundles différents.
- **Non-rejeu** : `bundle_id` + `chunk_index` empêche de rejouer un chunk d'un ancien bundle.

### Validation séquentielle

Le lecteur DOIT valider les chunks dans l'ordre séquentiel :
1. Vérifier que `chunk_index` correspond à l'index attendu.
2. Déchiffrer et vérifier l'auth tag avec l'AAD structurée.
3. Si échec, rejeter immédiatement le bundle entier.
4. Si succès, extraire les données et passer au chunk suivant.

**Exigences** :
- **REQ-BUN-12** — Chaque chunk DOIT être authentifié avec une AAD structurée incluant `bundle_id`, `chunk_index`, `chunk_count`, `is_last_chunk`, et `chunk_data_length`.
- **REQ-BUN-13** — Le lecteur DOIT rejeter tout chunk dont l'index ne correspond pas à l'index attendu (détection de réordonnancement).
- **REQ-BUN-14** — Le lecteur DOIT rejeter tout bundle si le flag `is_last_chunk` n'est pas positionné sur le dernier chunk (détection de troncature).

## Conformité cryptographique

**Référence** : [Guide ANSSI — Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques, version 3.00 (2026-03-20)](https://cyber.gouv.fr/publications/regles-et-recommandations-concernant-le-choix-et-le-dimensionnement-des-mecanismes-cryptographiques)

Les algorithmes utilisés dans le format de bundle sont conformes au guide ANSSI 3.00 :

- **AES-256-GCM-SIV** : conforme aux règles ET recommandations post-quantiques (taille de clé 256 bits, blocs 128 bits)
- **AES Key Wrap (RFC 5649)** : conforme, utilise AES-256 comme primitive sous-jacente
- **ECDSA P-256** : acceptable (non post-quantique, mais utilisé via TPM uniquement)
- **SHA-256** : conforme aux règles et recommandations

Voir [05-crypto.md](05-crypto.md) pour l'analyse détaillée de conformité.

## Questions ouvertes

1. Accès séquentiel strict ou reprise de téléchargement (seek par chunk) ?
2. Compression : avant chiffrement par chunk, ou format d'image déjà compressé ?
3. Une seule image par bundle ou plusieurs (rootfs, noyau, dtb…) avec ordre imposé ?
4. Chiffrement : une clé de contenu par bundle encapsulée pour N destinataires ?
5. Représentation du manifeste (CBOR, TLV, autre) ; alignement avec IETF SUIT (RFC 9124) ?
6. Taille de chunk, et bornes maximales acceptées par le lecteur.
7. Champ `tree_root` : l'authentification des chunks reposant sur la chaîne AEAD (voir ci-dessus), le champ est-il conservé (arbre de hachage) ou retiré du header ?
8. Paramètres AEAD du manifeste (nonce, AAD) : le manifeste est-il le chunk d'indice 0 ou une structure distincte ? Non spécifié à ce stade.
9. L'IV de 12 octets embarqué dans la clé de session (44 octets) n'est pas utilisé par la dérivation de nonce des chunks : le retirer (clé de 32 octets, `wrapped_session_key` de 40 octets) ou préciser son rôle ?
10. Emplacement des signatures Ed25519 + ML-DSA évoquées dans [05-crypto.md](05-crypto.md) : le header n'embarque que la signature ECDSA P-256 (vérifiée par le TPM). Ces signatures sont-elles les « signatures internes » du manifeste ?
