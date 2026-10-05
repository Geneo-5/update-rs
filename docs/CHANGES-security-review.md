# Modifications suite à la revue de sécurité

**Date** : 2026-10-06  
**Statut** : Appliquées

Ce document résume les modifications apportées à la spécification suite à l'analyse de sécurité approfondie.

## Résumé des décisions

### 1. KEK ne quitte jamais le TPM

**Décision** : Le mécanisme x3 n'est plus rejeté. Il est redéfini comme un mécanisme de **policy TPM restreinte** avec 3 branches d'autorisation, où la KEK reste toujours dans le TPM.

**Impact** :
- REQ-THR-4 clarifiée : mentionne le mécanisme x3 comme alternative acceptable si le TPM ne supporte pas AES Keywrap
- 03-tpm.md : nouvelle section détaillant le mécanisme x3 (policies, propriétés de sécurité, exigences)
- 07-security-analysis.md : option 3 reclassée de "REJETÉ" à "ALTERNATIVE ACCEPTABLE"
- ADR-0002 : mise à jour pour refléter que le mécanisme x3 est acceptable

**Justification** : Si les 3 déchiffrements sont effectués par le TPM avec une KEK non exportable, la KEK ne quitte jamais le TPM. Le mécanisme x3 n'expose donc pas la KEK en RAM. Il permet de limiter les commandes et arguments autorisés via plusieurs branches de policy TPM.

### 2. Format de bundle cryptographiquement fixé

**Décision** : Authentification des chunks par chaîne AEAD avec AAD structurée.

**Spécification** :
- Chaque chunk est chiffré/authentifié avec AES-256-GCM-SIV
- Nonce dérivé via HKDF de (session_key, bundle_id, chunk_index)
- AAD structurée : `bundle_id || chunk_index || chunk_count || is_last_chunk || chunk_data_length`

**Propriétés garanties** :
- Intégrité (auth tag 128-bit)
- Non-réordonnancement (chunk_index dans AAD)
- Non-troncature (is_last_chunk + chunk_count)
- Non-mix-and-match (bundle_id dans AAD)
- Non-rejeu (bundle_id + chunk_index)

**Impact** : 02-bundle-format.md mis à jour, "pistes pour l'authentification des chunks" remplacée par une décision ferme.

### 3. Architecture supervisor/worker

**Décision** : Séparation explicite du daemon en deux composants :

**Supervisor (privilégié, root)** :
- Accès TPM, MTD, filesystem
- Application de la policy machine
- Activation/commit

**Worker (sandboxé, non-root)** :
- Parsing du bundle et du manifeste
- Validation et transformation
- Retourne une représentation interne validée (IR)

**Impact** : 01-threat-model.md, 06-jail.md, 07-security-analysis.md mis à jour.

### 4. Phase Critique de Mise à Jour (CUP)

**Décision** : Toute opération transformant des données du bundle en état persistant est traitée comme une phase critique de sécurité.

**Inclus** :
- Parsing, validation, migration de format
- Génération de configuration
- Écriture MTD/filesystem
- Modification de permissions/ownership
- Création de symlinks

**Propriété de sécurité** : Le contenu du bundle est traité comme **hostile** jusqu'à validation, même s'il est signé.

**Impact** : 01-threat-model.md, 07-security-analysis.md mis à jour.

### 5. Chaîne de boot vérifiée

**Décision** : Le TPM doit être ancré dans une chaîne de confiance depuis le ROM/SoC secure boot.

**Chaîne requise** :
```
ROM/SoC secure boot
        ↓
bootloader vérifié
        ↓
kernel vérifié
        ↓
rootfs vérifié
        ↓
updated vérifié
        ↓
TPM policy/PCR
```

**Impact** : REQ-THR-6 ajoutée, 03-tpm.md mis à jour, questions ouvertes ajoutées.

### 6. Jail : manifeste comme capability policy

**Décision** : Le JailManifest est une demande de capacités validée contre une policy machine indépendante du bundle.

**Principe** :
```
Bundle demande → POLICY (machine) → allowed? → jail ou reject
```

**Impact** : 06-jail.md complètement réécrit pour refléter ce modèle.

### 7. API de sortie contrôlée (remplacement de host_bind_back)

**Décision** : Remplacement de `host_bind_back` générique par une API restrictive où le supervisor fournit un descripteur contrôlé.

**Problème résolu** : Élimination de la primitive d'écriture `payload → fichier arbitraire sur l'hôte`.

**Impact** : 06-jail.md mis à jour.

### 8. Résolution de chemins sécurisée

**Décision** : Utilisation de `openat2()` avec flags `RESOLVE_*` au lieu de `realpath()` + `open()`.

**Flags utilisés** :
- `RESOLVE_NO_SYMLINKS` : empêche le suivi de symlinks
- `RESOLVE_BENEATH` : empêche l'évasion via `..` ou chemins absolus
- `RESOLVE_NO_MAGICLINKS` : empêche le suivi de liens magiques

**Impact** : 06-jail.md mis à jour, TOCTOU éliminé.

### 9. Signal handlers async-signal-safe

**Décision** : Les handlers POSIX ne doivent pas effectuer de cleanup complexe directement.

**Implémentation** :
- Handler positionne un flag atomique (`AtomicBool`)
- Thread principal détecte le flag et effectue le cleanup
- Handler se contente d'opérations async-signal-safe (envoyer SIGKILL)

**Impact** : 06-jail.md, 04-update-flow.md mis à jour.

### 10. Limites de ressources (cgroups)

**Décision** : Le jail doit être contraint en ressources via cgroups v2.

**Limites appliquées** :
- PID : 64 max (anti-fork-bomb)
- Mémoire : 256M max
- CPU : 50% (1 CPU sur 2)
- I/O : 10 MB/s

**Impact** : 06-jail.md mis à jour.

### 11. Cleanup garanti après crash

**Décision** : Les mounts orphelins ne doivent pas persister au-delà du prochain boot.

**Mécanismes** :
1. Cleanup au démarrage (scan de /proc/mounts)
2. Cleanup périodique (timer systemd)
3. Cleanup au prochain boot (service systemd conditionnel)

**Impact** : 06-jail.md, 04-update-flow.md mis à jour.

## Corrections de cohérence documentaire

### RFC 3394 → RFC 5649

**Fichiers modifiés** :
- ADR-0002 : référence corrigée
- 05-crypto.md : référence corrigée
- 02-bundle-format.md : référence corrigée

**Justification** : RFC 5649 supporte les tailles arbitraires (non multiples de 8 octets), ce qui est nécessaire pour notre clé de session (44 octets).

### Taille wrapped_session_key

**Avant** : 40 octets (incohérent avec RFC 5649)

**Après** : 56 octets

**Calcul** :
- Plaintext : 44 octets (Key 32 + IV 12)
- Padding RFC 5649 : 44 → 48 octets (multiple de 8)
- Header RFC 5649 : 8 octets
- **Ciphertext final : 8 + 48 = 56 octets**

**Fichiers modifiés** : 02-bundle-format.md, 03-tpm.md, 05-crypto.md, ADR-0002.

### Structure du header

**Avant** :
- Offset 92 : wrapped_session_key (40 octets)
- Offset 132 : keywrap_alg (4 octets)
- Offset 136 : kek_id (32 octets)
- Offset 168 : ecc_signature_r (32 octets)
- Offset 200 : ecc_signature_s (32 octets)
- Offset 232 : padding (280 octets)

**Après** :
- Offset 92 : tree_root (32 octets) [inchangé]
- Offset 132 : keywrap_alg (4 octets) [inchangé]
- Offset 136 : kek_id (32 octets) [inchangé]
- Offset 168 : bundle_id (32 octets) [nouveau]
- Offset 200 : wrapped_session_key (56 octets) [déplacé et agrandi]
- Offset 256 : ecc_signature_r (32 octets) [déplacé]
- Offset 288 : ecc_signature_s (32 octets) [déplacé]
- Offset 320 : padding (192 octets) [réduit]

**Justification** : Ajout de `bundle_id` pour l'AAD structurée des chunks, et correction de la taille de `wrapped_session_key`.

### PolicyAuthorize : mécanisme précisé

**Avant** : Description vague de `TPM2_VerifySignature` établissant directement la relation.

**Après** : Séquence détaillée :
1. Pré-calcul de la policy digeste lors du provisioning
2. Signature de la policy par l'éditeur
3. Vérification runtime par le TPM via `TPM2_VerifySignature`

**Impact** : 03-tpm.md mis à jour.

## Fichiers modifiés

1. **docs/spec/01-threat-model.md**
   - REQ-THR-4, 5, 6, 7, 8 mises à jour
   - Section "Phase Critique de Mise à Jour" ajoutée
   - Architecture supervisor/worker ajoutée
   - Questions ouvertes mises à jour

2. **docs/spec/02-bundle-format.md**
   - Structure du header mise à jour (bundle_id, wrapped_session_key)
   - Section "Authentification des chunks" complètement réécrite
   - AAD structurée spécifiée
   - REQ-BUN-12, 13, 14 ajoutées

3. **docs/spec/03-tpm.md**
   - Suppression du fallback x3
   - Mécanisme PolicyAuthorize détaillé
   - Support TPM de AES Keywrap précisé
   - REQ-TPM-6, 10, 11 mises à jour/ajoutées
   - Questions ouvertes mises à jour

4. **docs/spec/05-crypto.md**
   - RFC 3394 → RFC 5649
   - Calcul de taille wrapped_session_key précisé
   - REQ-CRY-5 mise à jour
   - Question ouverte ajoutée (nonce AES-GCM-SIV)

5. **docs/spec/06-jail.md**
   - Modèle de sécurité complètement réécrit (capability policy)
   - Architecture supervisor/worker ajoutée
   - Résolution de chemins sécurisée (openat2)
   - API de sortie contrôlée (remplacement de host_bind_back)
   - Limites de ressources (cgroups) ajoutées
   - Cleanup garanti après crash ajouté
   - Signal handlers async-signal-safe précisés
   - Surface d'attaque mise à jour (J10, J11 ajoutés)

6. **docs/spec/07-security-analysis.md**
   - A9 : mitigations mises à jour (supervisor/worker, CUP)
   - Section 2.3 : fallback x3 supprimé, support TPM AES Keywrap précisé
   - Questions ouvertes mises à jour

7. **docs/adr/0002-tpm-kek-policy-signature.md**
   - Suppression du fallback x3
   - RFC 3394 → RFC 5649
   - Taille wrapped_session_key corrigée (40 → 56 octets)
   - Justification mise à jour (KEK ne quitte jamais le TPM)
   - Références mises à jour

## Questions ouvertes restantes

1. Quel bootloader (U-Boot) et quel mécanisme de secure boot pour ancrer la chaîne de confiance jusqu'au TPM ?
2. Comment mesurer et étendre les PCRs pour le bootloader, kernel, et rootfs ?
3. Politique de rollback du compteur NV : comment empêcher un attaquant de faire revenir le compteur en arrière ?
4. AES-GCM-SIV : nonce dérivé de manière déterministe (HKDF) ou aléatoire (CSPRNG) ?

## Prochaines étapes recommandées

1. **Implémentation** : Commencer par le worker (parsing, validation) dans un crate dédié avec `#![forbid(unsafe_code)]`.

2. **Policy machine** : Définir la structure de la policy machine (caps_whitelist, devices_whitelist, paths_whitelist) dans un fichier de configuration indépendant du bundle.

3. **Tests** : Mettre en place des tests de fuzzing sur le parser du manifeste et des chunks.

4. **Audit** : Planifier un audit de sécurité avant la mise en production, en se concentrant sur :
   - Le supervisor (surface de code privilégiée)
   - Le parser du manifeste (traité comme hostile)
   - L'implémentation cryptographique (AES Keywrap, AES-GCM-SIV)
   - L'intégration TPM (PolicyAuthorize, sessions chiffrées)

5. **Documentation** : Créer un guide de déploiement spécifiant :
   - Les exigences TPM (support AES Keywrap obligatoire)
   - La configuration de la chaîne de boot secure
   - La configuration de la policy machine
   - Les limites de ressources recommandées

## Conclusion

Les modifications appliquées renforcent significativement le modèle de sécurité :

- **KEK protégée** : ne quitte jamais le TPM
- **Chaîne cryptographique** : authentification des chunks complètement spécifiée
- **Surface d'attaque réduite** : architecture supervisor/worker, policy machine
- **TOCTOU éliminé** : openat2() avec RESOLVE_*
- **Défense en profondeur** : cgroups, signal handlers async-signal-safe, cleanup garanti

La spécification est maintenant suffisamment robuste pour passer à une implémentation de confiance, sous réserve de traiter les questions ouvertes restantes (chaîne de boot, PCRs, rollback du compteur NV).
