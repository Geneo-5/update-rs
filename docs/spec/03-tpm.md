# 03 — Rôle du TPM 2.0

Statut : Brouillon

Voir ADR : [ADR-0002](../adr/0002-tpm-kek-policy-signature.md).

## Ce que le TPM apporte, et ses limites

Un TPM 2.0 courant ne fait ni chiffrement de masse à bon débit, ni X25519, ni ML-KEM
(RSA et ECC NIST/BN uniquement). La garantie est donc obtenue **indirectement** : le TPM
protège les clés et conditionne leur usage à l'état de la plateforme ; le chiffrement du
payload se fait en logiciel avec une clé de session dérivée et encapsulée par le TPM.

**Cible** : TPM 2.0 en révision 1.59 de la Library Specification TCG. Les commandes et algorithmes décrits ci-dessous DOIVENT être validés par rapport à cette révision et aux capacités réelles du composant (`TPM2_GetCapability`).

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
2. **Restriction d'usage** : La KEK NE DOIT PAS pouvoir être utilisée pour signer, chiffrer, ou être descellée hors de son contexte de policy (`TPMA_OBJECT` : `decrypt=1`, `sign=0`, `restricted=0`, `fixedTPM=1`, `fixedParent=1`).

**Mécanisme TPM 2.0** :
- `TPM2_PolicyAuthorize` : l'autorité de vérification (clé ECC publique dans le TPM) signe un digest de policy approuvé. Si la signature est valide, la policy de la KEK est satisfaite.
- Alternative : `TPM2_PolicySecret` ou `TPM2_PolicySigned` avec la clé de vérification.

**Lien signature ↔ usage de la KEK** : la signature du header sert de **token de vérification**. Le TPM vérifie la signature ECDSA du header avant de satisfaire la policy de la KEK. L'altération du header en RAM du processus n'est pas un scénario vraisemblable : le header est reçu via socket stream et traité immédiatement par le processus fils de vérification.

### Clé de session (master key)

La clé de session (master key de 256 bits, dont les clés de chunk sont dérivées par HKDF) est générée côté éditeur pour chaque bundle, puis **encapsulée avec AES Key Wrap with Padding (RFC 5649)** par la KEK. Le résultat (ciphertext de 40 octets pour une clé de 32 octets) est placé dans le header du bundle.

**Note** : RFC 5649 est retenu pour sa généralité (tailles non multiples de 8 octets) ; avec une clé de 32 octets, RFC 3394 donnerait la même taille de ciphertext (question ouverte 9 de [05-crypto.md](05-crypto.md)).

### Déchiffrement de la clé de session

**Processus** (cas nominal : le TPM supporte AES Keywrap nativement ; sinon, voir « Mécanisme alternatif x3 » plus bas) :

1. Le **TPM calcule lui-même le hash du header** via `TPM2_HashSequenceStart` + `TPM2_SequenceUpdate` + `TPM2_SequenceComplete` (mode PCR process). Le buffer du header est transmis par chunks au TPM.
2. Le TPM vérifie la signature ECC du header via `TPM2_VerifySignature` sur le hash qu'il a calculé.
3. Le TPM satisfait la policy de la KEK via `PolicyAuthorize` (voir détail ci-dessous).
4. Le TPM déchiffre directement la clé de session encapsulée (AES Keywrap RFC 5649) via `TPM2_Duplicate` ou `TPM2_Unwrap` et la retourne au logiciel (dans une session chiffrée).
5. La KEK **ne quitte jamais le TPM**. Seule la clé de session (32 octets) est retournée au logiciel.

### Mécanisme `PolicyAuthorize` (détail)

`PolicyAuthorize` permet de conditionner l'usage d'une clé (la KEK) à la validation d'une policy par une autorité de signature (la clé de vérification ECC).

**Séquence** :
1. **Pré-calcul du digest de policy** : lors du provisioning, la policy complète de la KEK est calculée sous forme de digest (SHA-256). Notation simplifiée : le TPM calcule en réalité le digest par extensions successives (`H(digest_précédent || commandCode || arguments)`).
   ```
   policyDigest = SHA256(
     TPM2_PolicyCommandCode(TPM2_CC_Duplicate) ||
     TPM2_PolicyPCR(pcr_selection, pcr_digest) [optionnel]
   )
   ```
2. **Signature de la policy** : l'éditeur signe cette policy avec sa clé privée ECC P-256 :
   ```
   policySignature = ECDSA_Sign(private_key, policyDigest)
   ```
3. **Vérification runtime** : lors de la mise à jour, le logiciel envoie au TPM :
   - La policy (reconstruite dynamiquement)
   - La signature `policySignature`
   - La clé publique de vérification (déjà dans le TPM)
   
   Le TPM vérifie la signature via `TPM2_VerifySignature` et, si valide, satisfait la policy de la KEK.

**Avantage** : la policy peut être mise à jour côté éditeur (en changeant la signature) sans re-provisionner la KEK dans le TPM.

### Support TPM de AES Keywrap

**Deux modes d'encapsulation sont supportés** (le choix dépend du TPM cible) :

1. **Mode natif** : le TPM supporte AES Key Wrap (RFC 5649) via une commande spécifique (`TPM2_Duplicate` ou `TPM2_Unwrap` selon l'implémentation).
2. **Mode x3** : le TPM ne supporte pas AES Key Wrap, mais supporte `TPM2_EncryptDecrypt2` avec AES-ECB. Un mécanisme alternatif utilisant 3 déchiffrements AES via policies TPM restreintes est utilisé.

**Vérification au provisioning** : lors du provisioning, le fabricant DOIT vérifier lequel des deux modes est supporté par le TPM (`TPM2_GetCapability`). Si le TPM ne supporte ni l'un ni l'autre, il DOIT être rejeté.

**Pas de fallback logiciel** : aucun fallback logiciel n'est prévu. La KEK ne quitte jamais le TPM, et le TPM effectue le déchiffrement en interne.

> **À vérifier avant implémentation** : la spécification TPM 2.0 (révision 1.59) ne définit ni commande `TPM2_Unwrap`, ni AES Key Wrap (RFC 3394/5649). `TPM2_Duplicate` sert à dupliquer un objet TPM vers un nouveau parent (enveloppe interne propre au TPM) et ne déballe pas une clé arbitraire fournie par le logiciel ; le chiffrement symétrique générique passe par `TPM2_EncryptDecrypt2` (modes ECB/CBC/CFB/CTR/OFB selon le composant, sans GCM ni key wrap). REQ-TPM-6 et REQ-THR-4 supposent donc une capacité à confirmer sur le TPM cible (question ouverte 5) ; le mécanisme x3 ci-dessous est l'alternative à étudier en priorité.

### Mécanisme x3 : 3 déchiffrements AES via policies TPM restreintes

Si le TPM ne supporte pas AES Keywrap (RFC 5649) nativement, le mécanisme x3 est utilisé. Ce mécanisme n'est **pas** un fallback qui exposerait la KEK en RAM : la KEK reste dans le TPM, et le TPM effectue 3 déchiffrements AES séparés via des policies restreintes.

#### Principe

La clé de session (32 octets) est encapsulée côté éditeur dans un format décomposable en 3 opérations AES-ECB distinctes. Chaque opération est autorisée par une branche de policy distincte dans le TPM.

#### Encapsulation côté éditeur (x3)

1. Générer la clé de session `S` (32 octets).
2. Calculer un tag d'intégrité : `T = HMAC-SHA256(KEK, S)[0..8]` (8 octets).
3. Construire le plaintext encapsulé : `P = T || S` (40 octets).
4. Découper P en 3 blocs de 16 octets (padding PKCS#7 pour le dernier) :
   - `B1 = P[0..16]`
   - `B2 = P[16..32]`
   - `B3 = P[32..40] || 0x08^8` (8 octets de données + 8 octets de padding)
5. Chiffrer chaque bloc avec la KEK en AES-256-ECB :
   - `C1 = AES_Encrypt(KEK, B1)`
   - `C2 = AES_Encrypt(KEK, B2)`
   - `C3 = AES_Encrypt(KEK, B3)`
6. Placer `C1 || C2 || C3` dans le header (48 octets).

#### Déchiffrement côté device (x3, via TPM)

Le TPM effectue 3 déchiffrements AES-ECB via `TPM2_EncryptDecrypt2`, chacun autorisé par une branche de policy distincte :

**Branche 1 — Déchiffrement de C1** :
```text
Policy = PolicyCommandCode(TPM2_CC_EncryptDecrypt2)
       + PolicyCpHash(cpHash1)
       + PolicyAuthorize(signing_key)
```
où `cpHash1 = SHA256(TPM2_CC_EncryptDecrypt2 || keyName || decrypt || ECB || C1)`.

**Branche 2 — Déchiffrement de C2** :
```text
Policy = PolicyCommandCode(TPM2_CC_EncryptDecrypt2)
       + PolicyCpHash(cpHash2)
       + PolicyAuthorize(signing_key)
```
où `cpHash2 = SHA256(TPM2_CC_EncryptDecrypt2 || keyName || decrypt || ECB || C2)`.

**Branche 3 — Déchiffrement de C3** :
```text
Policy = PolicyCommandCode(TPM2_CC_EncryptDecrypt2)
       + PolicyCpHash(cpHash3)
       + PolicyAuthorize(signing_key)
```
où `cpHash3 = SHA256(TPM2_CC_EncryptDecrypt2 || keyName || decrypt || ECB || C3)`.

Chaque branche lie cryptographiquement les arguments de la commande (cpHash), ce qui empêche le TPM de déchiffrer d'autres données que C1, C2, ou C3. La signature de l'éditeur (PolicyAuthorize) est requise pour chaque branche.

#### Assemblage côté logiciel

Le logiciel reçoit les 3 plaintexts B1, B2, B3 du TPM, les assemble en P, vérifie le tag HMAC, et extrait la clé de session S.

#### Propriétés de sécurité

- La KEK reste dans le TPM.
- Aucune opération d'export, de duplication ou d'extraction de la KEK n'est autorisée.
- Seul un déchiffrement AES autorisé (C1, C2, ou C3) peut être demandé.
- Les arguments de la commande sont contraints par cpHash.
- Le plaintext déchiffré (B1, B2, B3) peut être retourné à `updated`.
- La clé de session (32 octets) peut se trouver en RAM dans `updated`.
- Une compromission d'`updated` peut exposer la session key déchiffrée, mais pas la KEK.

#### Exigences spécifiques au mécanisme x3

- REQ-TPM-X1 : la KEK doit être une clé TPM non exportable.
- REQ-TPM-X2 : la KEK ne doit jamais être retournée en clair hors du TPM.
- REQ-TPM-X3 : le déchiffrement doit être effectué par le TPM via une commande AES decrypt explicitement autorisée.
- REQ-TPM-X4 : la policy doit limiter la commande autorisée (`PolicyCommandCode`).
- REQ-TPM-X5 : la policy doit limiter les arguments de la commande (`PolicyCpHash`).
- REQ-TPM-X6 : les trois branches x3 doivent être décrites, auditées et limitées au strict nécessaire.
- REQ-TPM-X7 : la signature de l'éditeur (PolicyAuthorize) doit être requise pour chaque branche.

### Sessions chiffrées via certificat ECC du TPM

Toutes les commandes TPM sensibles (`TPM2_Unseal`, `TPM2_Duplicate`, `TPM2_VerifySignature` avec résultat policy) DOIVENT être exécutées dans une **session chiffrée et authentifiée** (`TPMA_SESSION` : `encrypt=1`, `decrypt=1`, `audit=0`) :

- Le sel de session est dérivé d'un échange ECDH avec une clé de chiffrement du TPM, l'**Endorsement Key (EK)** ou la SRK. Une **Attestation Key (AK)** est une clé de signature et ne peut pas servir de clé de salage (question ouverte 14).
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
4. Le fils retourne la clé de session au père via un **pipe Unix sécurisé**, puis se termine.
5. Le père (root) zeroize le buffer du header et utilise la clé de session pour la suite.

**Communication père-fils** : un **pipe Unix** (`pipe()`) est utilisé pour la transmission de la clé de session. Sur les architectures où les pipes ne sont pas disponibles ou insuffisants (ex: besoin de shared memory pour de gros buffers), une **mémoire partagée** (`shm_open()` + `mmap()`) peut être utilisée. Le pipe est préféré pour sa simplicité et son isolation (pas de fichier temporaire sur le disque).

**Avantages** :
- Isolation : si le fils est compromis pendant la vérification, l'attaquant n'a pas accès au daemon complet.
- Minimisation : le fils n'a pas besoin de toutes les capacités du daemon, seulement l'accès TPM.

## Exigences

- **REQ-TPM-1** — Les sessions TPM sensibles DOIVENT être salées, chiffrées et authentifiées (via une clé de chiffrement ECC du TPM : EK ou SRK).
- **REQ-TPM-2** — L'ancre de confiance (hash des clés publiques de vérification ECC) DOIT être stockée dans un index NV verrouillé en écriture.
- **REQ-TPM-3** — Un compteur NV monotone DOIT porter l'anti-rollback ; il n'est incrémenté qu'après validation d'une mise à jour (commit). Le compteur DOIT utiliser l'attribut `TPMA_NV_COUNTER` du TPM, qui garantit qu'il ne peut que s'incrémenter (pas de décrément, pas de réinitialisation sans clear TPM).
- **REQ-TPM-4** — Les secrets descellés (KEK, clé de session) DOIVENT être zeroizés après usage (`mlock` + `madvise(DONTDUMP)`) et ne jamais être swappés.
- **REQ-TPM-5** — La KEK DOIT avoir `sign=0`, `decrypt=1`, `restricted=0` dans ses attributs `TPMA_OBJECT`.
- **REQ-TPM-6** — Le TPM cible DOIT supporter soit le déchiffrement AES Keywrap (RFC 5649) en interne via `TPM2_Duplicate` ou `TPM2_Unwrap` (mode natif), soit le mécanisme alternatif x3 (3 déchiffrements AES via policies TPM restreintes). Si le TPM ne supporte ni l'un ni l'autre, il DOIT être rejeté lors du provisioning.
- **REQ-TPM-7** — La KEK NE DOIT JAMAIS être utilisable hors de sa policy (aucun `authValue` simple ne doit permettre de contourner la policy).
- **REQ-TPM-8** — Le daemon de mise à jour DOIT tourner en tant que root et forker un processus fils dédié à la vérification du header.
- **REQ-TPM-9** — Le hash du header PEUT être calculé par le TPM lui-même via `TPM2_HashSequenceStart` + `SequenceUpdate` + `SequenceComplete` (mode PCR process), ou par le logiciel. Le header arrive en RAM du daemon via socket stream, et l'altération du header en RAM du processus n'est pas un scénario vraisemblable. Le calcul software du hash est acceptable si le TPM ne supporte pas `TPM2_HashSequenceStart`.
- **REQ-TPM-10** — La policy de la KEK DOIT utiliser `PolicyAuthorize` pour permettre la mise à jour de la policy côté éditeur sans re-provisionner la KEK dans le TPM.
- **REQ-TPM-11** — Le TPM DOIT être ancré dans une chaîne de boot vérifiée (secure boot → bootloader vérifié → kernel vérifié → rootfs vérifié → `updated` vérifié → TPM policy/PCR).

## Provisioning (esquisse)

1. **Clé primaire** : SRK (Storage Root Key) déterministe, créée sous la hiérarchie `TPM2_RH_OWNER`.
2. **Clé de vérification ECC** : clé publique P-256 (côté éditeur) chargée dans le TPM via `TPM2_LoadExternal` (publique uniquement, pas de partie privée).
3. **KEK AES-256** : créée via `TPM2_Create` avec `authPolicy` composée (PolicyAuthorize + PolicyPCR optionnel). Stockée scellée sous la SRK.
4. **Index NV de l'ancre de confiance** : hash de la clé de vérification ECC publique, verrouillé en écriture (`TPMA_NV_WRITEDEFINE`).
5. **Compteur NV anti-rollback** : index NV monotone (`TPMA_NV_COUNTER`).
6. **Sessions chiffrées** : EK (Endorsement Key) ECC P-256 déjà présente, ou SRK, comme clé de salage.
7. **Enrôlement** : export de la clé publique de vérification (pour référence), EK certificate, et attestation de la KEK vers le registre côté serveur.

## Conformité cryptographique

**Référence** : [Guide ANSSI — Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques, version 3.00 (2026-03-20)](https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf)

Les algorithmes utilisés dans l'architecture TPM sont conformes au guide ANSSI 3.00 :

- **KEK AES-256** : conforme aux règles ET recommandations post-quantiques (taille de clé 256 bits)
- **AES Key Wrap (RFC 5649)** : conforme, utilise AES-256 comme primitive sous-jacente
- **ECDSA P-256** : acceptable (non post-quantique, mais utilisé via TPM uniquement pour la vérification)
- **ECDH P-256** : acceptable (utilisé via TPM pour les sessions chiffrées)

**Note sur la taille de la KEK** : le guide ANSSI 3.00 recommande une taille minimale de 128 bits (règle) et 192 bits pour la sécurité post-quantique (recommandation). AES-256 (256 bits) dépasse ces exigences et est conforme.

Voir [05-crypto.md](05-crypto.md) pour l'analyse détaillée de conformité.

## Questions ouvertes

1. Quels PCR lier à la policy de la KEK, et qui les étend (bootloader, noyau, userspace) ?
2. Politique de reprise en cas de changement légitime de PCR (mise à jour du bootloader) ?
3. Bibliothèque côté Rust : `tss-esapi` (dépend de `tpm2-tss` en C) ; acceptable pour la TCB ?
4. Émulation de test : `swtpm` ; périmètre des tests matériels (les sessions chiffrées ECDH sont-elles supportées ?).
5. ~~Aucune commande TPM 2.0 standard n'implémente AES Key Wrap (RFC 5649) : quelle commande ou quel mécanisme réalise le déballage de la clé de session sur le TPM cible ?~~ **Résolu** : deux modes supportés (natif ou x3, voir section « Support TPM de AES Keywrap »).
6. ~~Rotation de la KEK : doit-elle être renouvelable en field, ou fixe à vie ?~~ **Résolu** : rotation supportée (voir `key-management.md` section 7.7 et propositions ANSSI/NIST).
7. ~~Support TPM de `TPM2_HashSequenceStart` : tous les TPM 2.0 le supportent-ils, ou faut-il un fallback software pour le hash ?~~ **Résolu** : le header arrive en RAM du daemon via socket stream, le calcul software du hash est acceptable (pas de risque d'altération en RAM du processus).
8. Performance du hash TPM : impact sur le temps de vérification du header (latence bus SPI/I2C) ?
9. ~~Communication père-fils : pipe Unix suffit-il, ou faut-il un canal sécurisé supplémentaire ?~~ **Résolu** : pipe Unix (ou shared memory selon l'architecture), voir section « Architecture du daemon ».
10. Quel bootloader (U-Boot) et quel mécanisme de secure boot pour ancrer la chaîne de confiance jusqu'au TPM ? **Hors scope** : secure boot imposé comme prérequis d'intégration (voir `prerequis-integration.md`).
11. Comment mesurer et étendre les PCRs pour le bootloader, kernel, et rootfs ? **Hors scope** : chaîne de boot imposée comme prérequis.
12. ~~Politique de rollback du compteur NV : comment empêcher un attaquant de faire revenir le compteur en arrière ?~~ **Résolu** : `TPMA_NV_COUNTER` garantit un incrément monotone (pas de décrément possible sans clear TPM).
13. ~~La policy de la KEK (`PolicyAuthorize`) autorise un digest de policy signé par l'éditeur, pas un header particulier : comment la signature du header est-elle liée à l'usage de la KEK ?~~ **Résolu** : token de vérification de signature (voir section « Policy de la KEK »). L'altération du header en RAM du processus n'est pas un scénario vraisemblable (le header est reçu via socket stream et traité immédiatement).
14. Clé de salage des sessions chiffrées : EK ou SRK ? (une AK ne convient pas, voir plus haut).
