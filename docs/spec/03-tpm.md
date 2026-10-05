# 03 — Rôle du TPM 2.0

Statut : Brouillon

Voir ADR : [ADR-0002](../adr/0002-tpm-kek-policy-signature.md).

## Ce que le TPM apporte, et ses limites

Un TPM 2.0 courant ne fait ni chiffrement de masse à bon débit, ni X25519, ni ML-KEM
(RSA et ECC NIST/BN uniquement). La garantie est donc obtenue **indirectement** : le TPM
protège les clés et conditionne leur usage à l'état de la plateforme ; le chiffrement du
payload se fait en logiciel avec une clé de session dérivée et encapsulée par le TPM.

## Architecture des clés et policies (profil retenu)

Le TPM héberge trois objets cryptographiques liés :

| Objet | Type | Usage | Exportable ? | Policy |
|---|---|---|---|---|
| **SRK** | Clé de stockage primaire (RSA-2048 ou ECC P-256) | Parent de tous les objets du projet | Non (fixe) | Aucune (ouverte) |
| **Clé de vérification ECC (publique)** | ECC P-256 (publique uniquement) | Vérification de la signature du header | Oui (publique) | Aucune |
| **KEK** | Clé symétrique AES-256 (scellée) | Déchiffrement AES Keywrap de la clé de session | Non | Policy composée (voir ci-dessous) |

### Policy de la KEK

La KEK a une `authPolicy` composée qui **autorise son usage en déchiffrement uniquement si** :

1. **Vérification de la signature ECC du header** : Le TPM doit avoir validé la signature ECDSA P-256 du header avec la clé de vérification stockée (publique).
2. **Restriction d'usage** : La KEK NE DOIT PAS pouvoir être utilisée pour signer, chiffrer, ou être déscellée hors de son contexte de policy (`TPMA_OBJECT` : `decrypt=1`, `sign=0`, `restricted=0`, `fixedTPM=1`, `fixedParent=1`).

**Mécanisme TPM 2.0** :
- `TPM2_PolicyAuthorize` : l'autorité de vérification (clé ECC publique dans le TPM) signe la policy digeste. Si la signature est valide, la policy de la KEK est satisfaite.
- Alternative : `TPM2_PolicySecret` ou `TPM2_PolicySigned` avec la clé de vérification.

### Clé de session (AES-GCM)

La clé de session (Key 256-bit + IV 96-bit) est générée côté éditeur pour chaque bundle, puis **encapsulée avec AES Key Wrap with Padding (RFC 5649)** par la KEK. Le résultat (ciphertext 40 octets pour Key+IV) est placé dans le header du bundle.

**Note** : RFC 5649 est préféré à RFC 3394 car il supporte des tailles arbitraires (non multiples de 8 octets). Voir [05-crypto.md](05-crypto.md).

### Déchiffrement de la clé de session

**Cas 1 — Le TPM supporte AES Keywrap nativement** (`TPM2_Duplicate` avec AES ou `TPM2_Unwrap` selon implémentation) :
1. Le **TPM calcule lui-même le hash du header** via `TPM2_HashSequenceStart` + `TPM2_SequenceUpdate` + `TPM2_SequenceComplete` (mode PCR process). Le buffer du header est transmis par chunks au TPM.
2. Le TPM vérifie la signature ECC du header via `TPM2_VerifySignature` sur le hash qu'il a calculé.
3. Le TPM satisfait la policy de la KEK (`PolicyAuthorize`).
4. Le TPM déchiffre directement la clé de session encapsulée et la retourne au logiciel (dans une session chiffrée).

**Cas 2 — Le TPM ne supporte pas AES Keywrap** (fallback avec 3 policies distinctes) :
1. **Policy 1** : vérification de signature ECC du header + vérification de la version du bundle (doit être ≥ `min_firmware_version` stocké en NV).
2. **Policy 2** : vérification que les paramètres d'entrée du déchiffrement (ciphertext, IV) correspondent au hash du header.
3. **Policy 3** : vérification du compteur NV anti-rollback (le bundle doit avoir un counter > counter actuel).
4. Si les 3 policies sont satisfaites, le TPM déscelle la KEK en RAM temporaire.
5. Le logiciel effectue le AES Keywrap unwrap en software avec la KEK déscellée.
6. La KEK est immédiatement zeroizée après usage.

**Note** : Le fallback n'est pas une répétition x3 de la même vérification (ce qui serait cryptographiquement inutile), mais une **composition de 3 policies distinctes** qui vérifient des aspects différents de la légitimité du déchiffrement.

### Sessions chiffrées via certificat ECC du TPM

Toutes les commandes TPM sensibles (`TPM2_Unseal`, `TPM2_Duplicate`, `TPM2_VerifySignature` avec résultat policy) DOIVENT être exécutées dans une **session chiffrée et authentifiée** (`TPMA_SESSION` : `encrypt=1`, `decrypt=1`, `audit=0`) :

- Le sel de session est dérivé d'un échange ECDH avec le certificat **Endorsement Key (EK)** ou **Attestation Key (AK)** du TPM.
- La clé de session AES est dérivée du secret partagé ECDH via KDF (`TPM2_KDFa`).
- Les paramètres de commande et la réponse sont chiffrés avec cette clé, protégeant contre l'écoute du bus SPI/I2C (attaquant A4).

## Architecture du daemon et processus de vérification

Le daemon de mise à jour (`updated`) DOIT tourner en tant que **root** pour pouvoir :
- Accéder au TPM (`/dev/tpm0`, `/dev/tpmrm0`)
- Monter/démonter des filesystems
- Créer des namespaces
- Écrire sur les devices (MTD, block devices)

**Processus de vérification du header** :
1. Le daemon (root) **fork un processus fils** dédié à la vérification.
2. Le fils reçoit le buffer du header en entrée.
3. Le fils communique avec le TPM pour calculer le hash, vérifier la signature, et déchiffrer la clé de session.
4. Le fils retourne la clé de session au père via un pipe sécurisé, puis se termine.
5. Le père (root) zeroize le buffer du header et utilise la clé de session pour la suite.

**Avantages** :
- Isolation : si le fils est compromis pendant la vérification, l'attaquant n'a pas accès au daemon complet.
- Minimisation : le fils n'a pas besoin de toutes les capacités du daemon, seulement l'accès TPM.

## Exigences

- **REQ-TPM-1** — Les sessions TPM sensibles DOIVENT être salées, chiffrées et authentifiées (via EK/AK ECC).
- **REQ-TPM-2** — L'ancre de confiance (hash des clés publiques de vérification ECC) DOIT être stockée dans un index NV verrouillé en écriture.
- **REQ-TPM-3** — Un compteur NV monotone DOIT porter l'anti-rollback ; il n'est incrémenté qu'après validation d'une mise à jour (commit).
- **REQ-TPM-4** — Les secrets déscellés (KEK, clé de session) DOIVENT être zeroizés après usage (`mlock` + `madvise(DONTDUMP)`) et ne jamais être swappés.
- **REQ-TPM-5** — La KEK DOIT avoir `sign=0`, `decrypt=1`, `restricted=0` dans ses attributs `TPMA_OBJECT`.
- **REQ-TPM-6** — Si le TPM ne supporte pas AES Keywrap, la policy de la KEK DOIT composer 3 vérifications distinctes : signature ECC + version du bundle + compteur NV anti-rollback.
- **REQ-TPM-7** — La KEK NE DOIT JAMAIS être utilisable hors de sa policy (aucun `authValue` simple ne doit permettre de contourner la policy).
- **REQ-TPM-8** — Le daemon de mise à jour DOIT tourner en tant que root et forker un processus fils dédié à la vérification du header.
- **REQ-TPM-9** — Le TPM DOIT calculer lui-même le hash du header via `TPM2_HashSequenceStart` + `SequenceUpdate` + `SequenceComplete` (mode PCR process). Le logiciel NE DOIT PAS calculer le hash en software.

## Provisioning (esquisse)

1. **Clé primaire** : SRK (Storage Root Key) déterministe, créée sous la hiérarchie `TPM2_RH_OWNER`.
2. **Clé de vérification ECC** : clé publique P-256 (côté éditeur) chargée dans le TPM via `TPM2_LoadExternal` (publique uniquement, pas de partie privée).
3. **KEK AES-256** : créée via `TPM2_Create` avec `authPolicy` composée (PolicyAuthorize + PolicyPCR optionnel). Stockée scellée sous la SRK.
4. **Index NV de l'ancre de confiance** : hash de la clé de vérification ECC publique, verrouillé en écriture (`TPMA_NV_WRITEDEFINE`).
5. **Compteur NV anti-rollback** : index NV monotone (`TPMA_NV_COUNTER`).
6. **Sessions chiffrées** : EK (Endorsement Key) ECC P-256 déjà présente, ou AK (Attestation Key) créée et certifiée par le fabricant.
7. **Enrôlement** : export de la clé publique de vérification (pour référence), EK certificate, et attestation de la KEK vers le registre côté serveur.

## Questions ouvertes

1. Quels PCR lier à la policy de la KEK, et qui les étend (bootloader, noyau, userspace) ?
2. Politique de reprise en cas de changement légitime de PCR (mise à jour du bootloader) ?
3. Bibliothèque côté Rust : `tss-esapi` (dépend de `tpm2-tss` en C) ; acceptable pour la TCB ?
4. Émulation de test : `swtpm` ; périmètre des tests matériels (les sessions chiffrées ECDH sont-elles supportées ?).
5. Taille de la KEK : 256-bit suffisante pour AES Key Wrap (RFC 5649), ou 128-bit acceptable pour performance sur TPM limité ?
6. Rotation de la KEK : doit-elle être renouvelable en field, ou fixe à vie ?
7. Support TPM de `TPM2_HashSequenceStart` : tous les TPM 2.0 le supportent-ils, ou faut-il un fallback software pour le hash ?
8. Performance du hash TPM : impact sur le temps de vérification du header (latence bus SPI/I2C) ?
9. Communication père-fils : pipe Unix suffit-il, ou faut-il un canal sécurisé supplémentaire (socket Unix + SCM_RIGHTS pour les fds TPM) ?
