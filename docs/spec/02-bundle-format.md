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
[ en-tête (header) ][ manifeste signé ][ chunk 0 ][ chunk 1 ] … [ chunk N (final) ]
```

L'en-tête a une **taille fixe** (padding éventuel) pour permettre un traitement en streaming sans prélecture coûteuse.

### Composition de l'en-tête (Header)

L'en-tête contient toutes les métadonnées nécessaires au traitement en streaming et à la vérification initiale. Il est intégralement couvert par une signature ECC (ECDSA P-256 sur SHA-256(header)).

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
| 92 | 40 | `wrapped_session_key` | **AES Key Wrap (RFC 5649)** de la clé de session (Key 256-bit + IV 96-bit + overhead = 40 octets) |
| 132 | 4 | `keywrap_alg` | `0x0001` = AES Key Wrap with Padding RFC 5649 |
| 136 | 32 | `kek_id` | Identifiant (hash) de la KEK cible dans le TPM |
| 168 | 32 | `ecc_signature_r` | Composante r de la signature ECDSA P-256 (32 octets) |
| 200 | 32 | `ecc_signature_s` | Composante s de la signature ECDSA P-256 (32 octets) |
| 232 | 280 | `padding` | Réservé, mis à zéro |

**Total : 512 octets** (alignement sur secteur flash)

**Note sur l'évolution du header** : si une future version nécessite un header plus grand (ex: 1024 octets), elle aura :
- Un `header_version` différent (ex: `0x0002`)
- Un `header_size` différent (ex: 1024)
- Le lecteur DOIT vérifier que `header_version` est supporté avant de lire les champs suivants

#### Détail des champs sensibles

- **Clé de session chiffrée** (`wrapped_session_key`, 40 octets) :
  - Une clé de session éphémère **AES-256-GCM-SIV** (Key 256-bit + IV 96-bit) est générée côté éditeur pour chaque bundle.
  - Cette clé est encapsulée avec **AES Key Wrap with Padding (RFC 5649)** par la KEK du dispositif cible.
  - Le résultat (ciphertext) est placé dans le header.
  - La KEK (Key Encryption Key) réside de manière non exportable dans le TPM du dispositif cible (voir `03-tpm.md`).

- **Signature ECC** (`ecc_signature_r` + `ecc_signature_s`) :
  - Signature ECDSA P-256 calculée sur `SHA-256(header[0..168])` (tous les champs sauf signature et padding).
  - La clé publique de vérification est stockée dans le TPM (publique uniquement).

### Flux de validation

1. **Extraction** : Le lecteur lit les 512 premiers octets du bundle (le header).
2. **Vérification de magic/version** : Rejet immédiat si magic ou `header_version` invalide.
3. **Vérification de taille** : `header_size` doit correspondre à la taille attendue pour cette version.
4. **Vérification anti-rollback (version)** : `bundle_version` doit être > dernière version installée (stockée dans un index NV TPM ou fichier persistant).
5. **Vérification anti-rollback (firmware)** : `min_firmware_version` doit être ≤ version firmware actuelle du device.
6. **Hash du header (par le TPM)** : Le lecteur transmet le buffer du header au TPM via `TPM2_HashSequenceStart` + `SequenceUpdate` + `SequenceComplete` (mode PCR process). Le TPM calcule lui-même `SHA-256(header[0..168])`.
7. **Vérification de signature ECC** : Le TPM vérifie la signature ECDSA via `TPM2_VerifySignature` sur le hash qu'il a calculé (sous session chiffrée).
8. **Déchiffrement de la clé de session** : Le TPM satisfait la policy de la KEK et déchiffre `wrapped_session_key` (sous session chiffrée). Voir `03-tpm.md` pour le détail et le fallback avec 3 policies distinctes.
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

## Pistes pour l'authentification des chunks (non tranché)

| Piste | Principe | Points à évaluer |
|---|---|---|
| Chaîne AEAD | AEAD par chunk, nonce dérivé de l'index, drapeau « dernier chunk » (type STREAM) | simplicité, détection de troncature, pas de saut en arrière |
| Arbre de hachage | Racine signée dans le manifeste, preuves par chunk | accès aléatoire, taille des preuves |
| Liste de hash dans le manifeste | Un hash par chunk dans l'en-tête signé | taille de l'en-tête, simplicité |

## Questions ouvertes

1. Accès séquentiel strict ou reprise de téléchargement (seek par chunk) ?
2. Compression : avant chiffrement par chunk, ou format d'image déjà compressé ?
3. Une seule image par bundle ou plusieurs (rootfs, noyau, dtb…) avec ordre imposé ?
4. Chiffrement : une clé de contenu par bundle encapsulée pour N destinataires ?
5. Représentation du manifeste (CBOR, TLV, autre) ; alignement avec IETF SUIT (RFC 9124) ?
6. Taille de chunk, et bornes maximales acceptées par le lecteur.
