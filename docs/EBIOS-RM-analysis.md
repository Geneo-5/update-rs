# Analyse EBIOS Risk Manager — update-rs

Statut : Brouillon (première itération)

> Cette analyse suit la méthodologie **EBIOS Risk Manager** de l'ANSSI [[1]], structurée en 5 ateliers itératifs.

---

## Atelier 1 : Cadrage et socle de sécurité

### 1.1 Objet de l'étude

**Système `update-rs`** : mécanisme de mise à jour sécurisé pour plateforme embarquée (SolidRun Clearfog), écrit en Rust, utilisant un TPM 2.0 pour l'ancrage de confiance.

**Périmètre** :
- Daemon `updated` (supervisor + worker)
- Format de bundle (header, manifeste, chunks chiffrés)
- Environnement d'exécution jail (sandbox)
- Chaîne de confiance TPM (KEK, sessions chiffrées, anti-rollback)

### 1.2 Mission

**Mission principale** : Permettre la mise à jour sécurisée d'une plateforme embarquée en garantissant :
- L'authenticité du logiciel installé (signature éditeur + TPM)
- La confidentialité du contenu (chiffrement AES-256-GCM-SIV)
- L'intégrité du processus (anti-rollback, détection de corruption)
- L'isolation du code exécuté (jail sandboxé)

### 1.3 Valeurs métier

| VM | Valeur métier | Description |
|---|---|---|
| **VM1** | Intégrité du firmware installé | Le code exécuté sur la plateforme doit être authentique et non modifié |
| **VM2** | Confidentialité du payload | Le contenu des bundles (code, configuration, données) ne doit pas être divulgué |
| **VM3** | Disponibilité de la plateforme | Le device ne doit pas être brické par une mise à jour ratée ou malveillante |
| **VM4** | Traçabilité des mises à jour | Chaque mise à jour doit être journalisée et auditable |
| **VM5** | Isolation du code tiers | Le payload exécuté ne doit pas pouvoir compromettre l'hôte |
| **VM6** | Confidentialité de la configuration hôte | Les fichiers de configuration système (/etc, /var, credentials, secrets locaux) ne doivent pas être divulgués |

### 1.4 Événements redoutés

| ER | Événement redouté | VM associée | Gravité | Justification |
|---|---|---|---|---|
| **ER1** | Installation d'un firmware malveillant (code non authentique) | VM1 | **G4 CRITIQUE** | Compromission totale du système, possibilité d'exfiltration de données, contrôle à distance, utilisation comme botnet |
| **ER2** | Divulgation du contenu d'un bundle (code source, secrets embarqués) | VM2 | **G3 GRAVE** | Perte de propriété intellectuelle, exposition de secrets (clés, algorithmes), avantage concurrentiel perdu |
| **ER3** | Brick du device après mise à jour ratée (corruption MTD, rollback impossible) | VM3 | **G3 GRAVE** | Device inutilisable, nécessité d'intervention physique (reprogrammation JTAG), coût de remplacement |
| **ER4** | Perte de traçabilité (logs supprimés, événements critiques non journalisés) | VM4 | **G2 SIGNIFICATIVE** | Impossible d'investiguer un incident, non-conformité réglementaire, difficulté à détecter une compromission |
| **ER5** | Évasion du jail (payload compromet l'hôte) | VM5 | **G4 CRITIQUE** | Escalade de privilèges root, accès au TPM, modification de l'anti-rollback, installation de firmware malveillant |
| **ER6** | Rollback forcé vers version vulnérable (attaquant abaisse le compteur) | VM1, VM3 | **G3 GRAVE** | Exploitation de vulnérabilités connues, contournement des correctifs de sécurité |
| **ER7** | Compromission de la KEK (extraction depuis le TPM) | VM1, VM2 | **G4 CRITIQUE** | Possibilité de déchiffrer tous les bundles passés et futurs (si même KEK), perte de confidentialité et d'authenticité |
| **ER8** | Déni de service sur le mécanisme de mise à jour (exhaustion TPM, boucle infinie) | VM3 | **G2 SIGNIFICATIVE** | Device ne peut plus recevoir de mises à jour, doit être redémarré physiquement |
| **ER9** | Divulgation de la configuration hôte (fichiers /etc, credentials, secrets locaux) | VM6 | **G3 GRAVE** | Exposition de mots de passe, clés SSH, certificats, configuration réseau, avantage pour attaques ultérieures |

### 1.5 Socle de sécurité (mesures spécifiées)

Le projet spécifie les mesures suivantes (aucune n'est encore implémentée : les crates sont des squelettes) :

| Mesure | Description | Couverture |
|---|---|---|
| **Signature ECDSA P-256 (header)** | Signature du header vérifiée par le TPM (`TPM2_VerifySignature`) ; signatures Ed25519 + ML-DSA (hybride post-quantique) prévues pour les artefacts internes, voir `05-crypto.md` | VM1 |
| **AES-256-GCM-SIV** | Chiffrement authentifié des chunks (AEAD) | VM2 |
| **KEK dans TPM** | Clé de chiffrement non exportable, déchiffrement effectué par le TPM | VM1, VM2 |
| **Sessions chiffrées TPM** | Protection des commandes sensibles sur le bus SPI/I2C | VM1, VM2 |
| **Anti-rollback NV TPM** | Compteur non volatil empêchant l'installation de versions anciennes | VM1 |
| **Architecture supervisor/worker** | Séparation privilèges (supervisor) / parsing (worker sandboxé) | VM1, VM5 |
| **Jail avec namespaces** | Isolation mount, ipc, uts, cgroup, net | VM5 |
| **Seccomp** | Filtre BPF limitant les syscalls dans le jail | VM5 |
| **Capabilities réduites** | Drop de toutes les caps non nécessaires | VM5 |
| **Securebits stricts** | Empêche la récupération de privilèges via setuid | VM5 |
| **Phase Critique de Mise à Jour (CUP)** | Traitement hostile de tout contenu issu du bundle | VM1, VM5 |
| **Policy machine indépendante** | Validation des capacités demandées contre une whitelist machine | VM5 |
| **openat2() + RESOLVE_*** | Résolution atomique de chemins (anti-TOCTOU) | VM5 |
| **mlockall + prctl** | Protection de la mémoire (pas de swap, pas de core dump) | VM1, VM2 |

### 1.6 Hypothèses de sécurité matérielle

Le système repose sur les hypothèses de sécurité matérielle suivantes :

| Hypothèse | Description | Niveau de confiance | Risque résiduel |
|---|---|---|---|
| **Secure boot hardware** | Le SoC dispose d'un ROM boot code immuable qui vérifie la signature du bootloader | 🔴 Haute (si correctement configuré) | Contournement possible via vulnérabilité ROM (rare) ou glitching hardware |
| **Secure boot software** | Le bootloader (U-Boot) vérifie la signature du kernel et du rootfs avant exécution | 🔴 Haute (si clés protégées) | Contournement possible si attaquant obtient accès root avant vérification |
| **JTAG désactivé** | Les interfaces de debug JTAG/SWD sont désactivées ou protégées par fuse/eFuse | 🟠 Moyenne (dépend de la configuration) | Réactivation possible via manipulation hardware (glitching, fault injection) |
| **Accès flash protégé** | La flash (eMMC/MTD) n'est pas accessible en lecture/écriture sans authentification | 🟠 Moyenne (dépend du hardware) | Extraction physique possible (dessoudage, lecteur de carte SD) |
| **TPM intégré** | Le TPM 2.0 est intégré au SoC ou connecté via bus sécurisé (SPI/I2C) | 🟠 Moyenne (dépend de l'implémentation) | Écoute du bus possible (sonde logique), réinitialisation TPM possible (clear TPM) |
| **Protection contre glitching** | Le SoC dispose de protections contre voltage/clock glitching | 🟡 Faible (dépend du hardware) | Glitching possible sur hardware non protégé, permettant de contourner secure boot ou d'extraire des clés |

**Note** : Ces hypothèses sont considérées comme vraies dans le cadre de cette analyse, mais peuvent être contournées par des attaques hardware avancées (glitching, side-channel, fault injection). La protection contre ces attaques relève de la sécurité physique du hardware et dépasse le périmètre de `update-rs`.

### 1.7 Écarts au socle de sécurité

| Écart | Description | Risque |
|---|---|---|
| **Chaîne de boot incomplète** | Pas encore d'ancrage depuis ROM/SoC secure boot → bootloader → kernel | Un attaquant A3 peut modifier le bootloader et contourner toute la chaîne de confiance |
| **Mécanisme x3 partiellement spécifié** | Principe et exigences REQ-TPM-X1 à X7 dans `03-tpm.md` ; les 3 branches de policy TPM ne sont pas encore décrites | Complexité, risque de mauvaise configuration |
| **Pas d'attestation distante** | Pas de `TPM2_Quote` pour prouver l'identité du TPM à un serveur distant | Impossible de détecter un TPM remplacé ou compromis |
| **Pas de rotation des clés** | KEK et clé de signature statiques | Si compromise, tous les bundles passés et futurs sont compromis |
| **Système A/B non intégré** | Spécifié (REQ-FLW-1 à 3) mais absent de la machine à états de `04-update-flow.md` et du code | Corruption possible si interruption pendant écriture MTD |

---

## Atelier 2 : Sources de risque

### 2.1 Sources de risque identifiées

| SR | Source de risque | Motivation | Ressources | Compétences |
|---|---|---|---|---|
| **SR1** | Attaquant réseau (MITM) | Intercepter, modifier, rejouer les bundles | Faibles (accès au réseau) | Moyennes (cryptanalyse, reverse engineering) |
| **SR2** | Détenteur d'un bundle légitime | Comprendre le contenu, créer un bundle modifié | Faibles (accès au fichier) | Élevées (cryptanalyse, reverse engineering) |
| **SR3** | Attaquant physique (accès flash hors tension) | Extraire ou modifier le firmware installé | Moyennes (équipement de lecture flash, JTAG) | Élevées (hardware hacking) |
| **SR4** | Attaquant physique (bus TPM) | Écouter/rejouer les commandes SPI/I2C | Élevées (sonde logique, analyseur de protocole) | Très élevées (cryptographie TPM) |
| **SR5** | Attaquant local (compromission root post-boot) | Installer un bundle malveillant, corrompre l'anti-rollback | Élevées (accès root) | Élevées (exploitation kernel, manipulation TPM) |
| **SR6** | Éditeur malveillant ou compromis | Signer un bundle contenant une backdoor | Très élevées (accès à la clé de signature) | Faibles (pas besoin de compétence technique) |
| **SR7** | Payload malveillant (jail) | Échapper au sandbox, escalader les privilèges | Faibles (code dans le jail) | Élevées (exploitation de vulnérabilités jail, kernel) |
| **SR8** | État-nation (APT) | Compromission persistante, exfiltration de données | Très élevées (zero-days, supply chain) | Très élevées (cryptographie, hardware, reverse engineering) |

### 2.2 Objectifs visés par les sources de risque

| OV | Objectif visé | SR concernées |
|---|---|---|
| **OV1** | Installer un firmware malveillant (backdoor, botnet) | SR1, SR3, SR5, SR6, SR8 |
| **OV2** | Divulguer le contenu d'un bundle (propriété intellectuelle, secrets) | SR2, SR3, SR4, SR8 |
| **OV3** | Bricker le device (déni de service) | SR1, SR3, SR5, SR7 |
| **OV4** | Abaisser le compteur anti-rollback (exploiter vulnérabilités connues) | SR3, SR5, SR8 |
| **OV5** | Échapper au jail et compromettre l'hôte | SR7 |
| **OV6** | Extraire la KEK (déchiffrer tous les bundles) | SR4, SR5, SR8 |
| **OV7** | Supprimer les logs (masquer une compromission) | SR5, SR7 |
| **OV8** | Divulguer la configuration hôte (credentials, secrets locaux) | SR3, SR5, SR7, SR8 |

### 2.3 Couples SR/OV retenus (prioritaires)

| Couple | Description | Priorité |
|---|---|---|
| **SR1/OV1** | MITM installe firmware malveillant | 🔴 Haute |
| **SR3/OV1** | Accès physique flash installe firmware malveillant | 🔴 Haute |
| **SR5/OV1** | Root post-boot installe firmware malveillant | 🔴 Haute |
| **SR7/OV5** | Payload échappe au jail | 🔴 Haute |
| **SR5/OV4** | Root abaisse l'anti-rollback | 🟠 Moyenne |
| **SR4/OV6** | Bus TPM extrait la KEK | 🟠 Moyenne |
| **SR2/OV2** | Détenteur bundle divulgue le contenu | 🟠 Moyenne |
| **SR5/OV8** | Root divulgue configuration hôte | 🟠 Moyenne |
| **SR7/OV8** | Payload divulgue configuration hôte | 🟠 Moyenne |
| **SR6/OV1** | Éditeur signe bundle malveillant | 🟡 Faible (traité par organisation des clés) |
| **SR8/* ** | APT (tous objectifs) | 🟡 Faible (hors périmètre actuel, défense en profondeur) |

---

## Atelier 3 : Scénarios stratégiques

### 3.1 Cartographie de l'écosystème

```
┌─────────────────────────────────────────────────────────┐
│                    ÉCOSYSTÈME                            │
│                                                          │
│  ┌──────────┐         ┌──────────┐         ┌────────┐  │
│  │ Éditeur  │────────▶│ Transport│────────▶│ Device │  │
│  │ (offline)│ sign +  │ (réseau, │ bundle  │(ClearFog)│ │
│  │          │ encrypt │ USB, SD) │         │        │  │
│  └──────────┘         └──────────┘         └────┬───┘  │
│                                                  │      │
│  ┌──────────────────────────────────────────────┴──┐   │
│  │                   Device (ClearFog)              │   │
│  │                                                   │   │
│  │  ┌─────────┐  ┌──────────┐  ┌────────────────┐  │   │
│  │  │ Bootloader│  │ Kernel   │  │ updated (daemon)│  │   │
│  │  │ (U-Boot)│  │ (Linux)  │  │                │  │   │
│  │  └────┬────┘  └────┬─────┘  └───────┬────────┘  │   │
│  │       │            │                │            │   │
│  │  ┌────▼────────────▼────────────────▼────────┐  │   │
│  │  │              TPM 2.0 (SPI/I2C)             │  │   │
│  │  │  - KEK (non exportable)                    │  │   │
│  │  │  - Index NV (anti-rollback)                │  │   │
│  │  │  - Sessions chiffrées                      │  │   │
│  │  │  - PCRs (mesures)                          │  │   │
│  │  └────────────────────────────────────────────┘  │   │
│  │                                                   │   │
│  │  ┌────────────────────────────────────────────┐  │   │
│  │  │              Jail (sandbox)                 │  │   │
│  │  │  - tmpfs + namespaces + seccomp            │  │   │
│  │  │  - Payload éphémère                        │  │   │
│  │  └────────────────────────────────────────────┘  │   │
│  │                                                   │   │
│  │  ┌────────────────────────────────────────────┐  │   │
│  │  │         Stockage (MTD / eMMC)               │  │   │
│  │  │  - Slot A (firmware actif)                  │  │   │
│  │  │  - Slot B (firmware inactif, si A/B)        │  │   │
│  │  │  - Configuration (/etc, /var)               │  │   │
│  │  └────────────────────────────────────────────┘  │   │
│  └───────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────┘
```

### 3.2 Scénarios stratégiques

#### SS1 : Attaque réseau sur le transport (SR1 → OV1)

**Chemin d'attaque** :
```
SR1 (MITM réseau)
  │
  ├─▶ Intercepte le bundle pendant le téléchargement
  │
  ├─▶ Tente de modifier le header (signature) → rejeté par vérification ECDSA P-256 (TPM)
  │
  ├─▶ Tente de modifier le manifeste (chiffré) → rejeté par AES-GCM-SIV (intégrité)
  │
  ├─▶ Tente de modifier les chunks (chiffrés) → rejeté par AES-GCM-SIV (intégrité)
  │
  ├─▶ Tente de rejouer un ancien bundle valide → rejeté par anti-rollback (compteur NV TPM)
  │
  └─▶ Tente de remplacer le bundle par un bundle signé pour un autre device → rejeté par kek_id + policy PCR
```

**Gravité** : **G4 CRITIQUE** (si réussi → ER1 : firmware malveillant installé)

**Vraisemblance** : **V1 Peu vraisemblable** (toutes les attaques réseau sont mitigées par cryptographie)

**Risque résiduel** : **FAIBLE**

---

#### SS2 : Attaque physique sur le stockage (SR3 → OV1)

**Chemin d'attaque** :
```
SR3 (accès physique flash hors tension)
  │
  ├─▶ Extrait la flash (dessoudage, lecteur de carte SD)
  │
  ├─▶ Tente de modifier le firmware installé
  │   │
  │   └─▶ Au prochain boot, vérification de signature échoue (si chaîne de boot complète)
  │       OU kernel panic (si pas de chaîne de boot)
  │
  ├─▶ Tente de modifier l'anti-rollback (fichier sur flash)
  │   │
  │   └─▶ Vérification TPM échoue (compteur NV TPM > compteur fichier)
  │
  └─▶ Tente de réinitialiser le TPM (clear TPM)
      │
      └─▶ KEK effacée → device bloqué (pas de déchiffrement possible)
```

**Gravité** : **G4 CRITIQUE** (si réussi → ER1 : firmware malveillant installé)

**Vraisemblance** : **V2 Vraisemblable** (accès physique requis, mais pas de chaîne de boot complète actuellement)

**Risque résiduel** : **MOYEN** (chaîne de boot incomplète, voir Atelier 5)

---

#### SS3 : Attaque locale post-boot (SR5 → OV1, OV4)

**Chemin d'attaque** :
```
SR5 (root post-boot, via vulnérabilité kernel ou service exposé)
  │
  ├─▶ Tente d'appeler directement `updated` avec un bundle malveillant
  │   │
  │   └─▶ Vérification TPM échoue (policy PCR, kek_id)
  │
  ├─▶ Tente de corrompre l'index NV TPM (anti-rollback)
  │   │
  │   └─▶ TPM refuse sans policy (accès protégé par authValue ou policy)
  │
  ├─▶ Tente d'intercepter la clé de session en RAM
  │   │
  │   └─▶ mlockall + prctl(PR_SET_DUMPABLE, 0) empêche swap et core dump
  │       MAIS : si accès root, peut potentiellement lire /proc/*/mem
  │
  └─▶ Tente de remplacer le binaire `updated`
      │
      └─▶ Vérification de signature au boot échoue (si chaîne de boot complète)
```

**Gravité** : **G4 CRITIQUE** (si réussi → ER1 : firmware malveillant installé)

**Vraisemblance** : **V3 Très vraisemblable** (accès root déjà obtenu, plusieurs vecteurs d'attaque)

**Risque résiduel** : **ÉLEVÉ** (surface d'attaque importante, nécessité de défense en profondeur)

---

#### SS4 : Évasion du jail (SR7 → OV5)

**Chemin d'attaque** :
```
SR7 (payload malveillant dans le jail)
  │
  ├─▶ Tente d'échapper via bind mount mal configuré
  │   │
  │   └─▶ Policy machine rejette les bind mounts non autorisés
  │
  ├─▶ Tente de créer un device node dangereux (/dev/mem, /dev/sda)
  │   │
  │   └─▶ Whitelist de device nodes + device cgroup
  │
  ├─▶ Tente d'utiliser /proc/sysrq-trigger pour reboot
  │   │
  │   └─▶ /proc monté en ro, sysrq-trigger masqué
  │
  ├─▶ Tente d'exploiter une vulnérabilité kernel via syscall
  │   │
  │   └─▶ Seccomp limite les syscalls autorisés
  │
  └─▶ Tente d'exécuter un binaire setuid root
      │
      └─▶ Securebits SECBIT_NOROOT empêche l'acquisition de caps
```

**Gravité** : **G4 CRITIQUE** (si réussi → ER5 : compromission de l'hôte)

**Vraisemblance** : **V2 Vraisemblable** (multiples couches de défense, mais surface d'attaque importante)

**Risque résiduel** : **MOYEN** (défense en profondeur, mais vulnérabilités kernel possibles)

---

#### SS5 : Extraction de la KEK via bus TPM (SR4 → OV6)

**Chemin d'attaque** :
```
SR4 (accès physique bus TPM SPI/I2C)
  │
  ├─▶ Sonde logique sur le bus TPM
  │
  ├─▶ Écoute les commandes de déchiffrement
  │   │
  │   └─▶ Sessions chiffrées TPM empêchent l'interception (AES-256)
  │
  ├─▶ Tente de rejouer une commande de déchiffrement
  │   │
  │   └─▶ Nonce/session unique empêche le rejeu
  │
  └─▶ Tente d'extraire la KEK directement depuis le TPM
      │
      └─▶ KEK non exportable (attribut `fixedTPM` + `fixedParent`)
```

**Gravité** : **G4 CRITIQUE** (si réussi → ER7 : KEK compromise, tous les bundles déchiffrables)

**Vraisemblance** : **V1 Peu vraisemblable** (sessions chiffrées, KEK non exportable)

**Risque résiduel** : **FAIBLE**

---

### 3.3 Synthèse des scénarios stratégiques

| Scénario | Gravité | Vraisemblance | Risque résiduel | Priorité |
|---|---|---|---|---|
| SS1 (réseau) | G4 | V1 | FAIBLE | 🟢 Basse |
| SS2 (physique flash) | G4 | V2 | MOYEN | 🟠 Moyenne |
| SS3 (local root) | G4 | V3 | ÉLEVÉ | 🔴 Haute |
| SS4 (évasion jail) | G4 | V2 | MOYEN | 🟠 Moyenne |
| SS5 (bus TPM) | G4 | V1 | FAIBLE | 🟢 Basse |

---

## Atelier 4 : Scénarios opérationnels

### 4.1 Biens supports critiques

| BS | Bien support | Rôle | Sensibilité |
|---|---|---|---|
| **BS1** | Daemon `updated` (supervisor) | Orchestration de la mise à jour, accès TPM, écriture MTD | 🔴 Critique |
| **BS2** | Daemon `updated` (worker) | Parsing du bundle, extraction des chunks | 🟠 Haute |
| **BS3** | TPM 2.0 | Stockage KEK, sessions chiffrées, anti-rollback | 🔴 Critique |
| **BS4** | Clé de session en RAM | Déchiffrement des chunks | 🟠 Haute |
| **BS5** | Jail (namespaces, seccomp, capabilities) | Isolation du payload | 🔴 Critique |
| **BS6** | Stockage MTD/eMMC | Firmware installé, configuration | 🔴 Critique |
| **BS7** | Bootloader (U-Boot) | Chaîne de boot, vérification kernel | 🔴 Critique |
| **BS8** | Kernel Linux | Syscalls, namespaces, cgroups | 🔴 Critique |

### 4.2 Scénarios opérationnels (détail technique)

#### SO1 : Compromission du supervisor via parser bug (SR5 → BS1)

**Enchaînement d'actions** :
1. **SR5** obtient root via vulnérabilité kernel (ex: CVE-2024-XXXX)
2. **SR5** crée un bundle malveillant avec un manifeste crafté (buffer overflow dans parser JSON)
3. **SR5** invoque `updated --bundle malicious.bundle`
4. **BS2** (worker) parse le manifeste, déclenche le buffer overflow
5. **SR5** obtient exécution de code dans le contexte du worker (non-root)
6. **SR5** exploite une vulnérabilité IPC pour escalader vers le supervisor (root)
7. **SR5** appelle directement le TPM pour déchiffrer un bundle malveillant
8. **BS1** (supervisor) écrit le firmware malveillant sur MTD

**Mitigations existantes** :
- Architecture supervisor/worker (isolation)
- Worker sandboxé (pas d'accès TPM, pas d'accès MTD)
- IPC minimal (validated IR uniquement)
- Seccomp sur le supervisor (limite les syscalls)

**Mitigations manquantes** :
- Chaîne de boot complète (vérification du binaire `updated` au boot)
- Attestation distante (détection de TPM remplacé)

**Vraisemblance** : **V2 Vraisemblable**

**Gravité** : **G4 CRITIQUE**

---

#### SO2 : Évasion du jail via symlink (SR7 → BS5)

**Enchaînement d'actions** :
1. **SR7** (payload) crée un symlink `/jail/etc/passwd → /etc/shadow` avant le verrouillage
2. **SR7** tente de lire `/jail/etc/passwd` pour extraire les hashes de mots de passe
3. **BS5** (jail) résout le symlink et lit `/etc/shadow` de l'hôte

**Mitigations existantes** :
- `MS_NOSYMFOLLOW` sur tous les bind mounts host→jail
- `openat2()` avec `RESOLVE_NO_SYMLINKS` pour la résolution de chemins
- Vérification de tous les chemins avant bind mount

**Mitigations manquantes** :
- Aucune (mitigations complètes)

**Vraisemblance** : **V1 Peu vraisemblable**

**Gravité** : **G3 GRAVE** (accès à /etc/shadow, mais pas root)

---

#### SO3 : Extraction de la clé de session via /proc/*/mem (SR5 → BS4)

**Enchaînement d'actions** :
1. **SR5** obtient root via vulnérabilité kernel
2. **SR5** attend que `updated` déchiffre la clé de session via le TPM
3. **SR5** lit `/proc/<pid_updated>/mem` pour extraire la clé de session en RAM
4. **SR5** utilise la clé de session pour déchiffrer les chunks d'un bundle

**Mitigations existantes** :
- `mlockall(MCL_CURRENT | MCL_FUTURE)` empêche le swap
- `prctl(PR_SET_DUMPABLE, 0)` empêche les core dumps
- `setrlimit(RLIMIT_CORE, 0)` désactive les core dumps

**Mitigations manquantes** :
- Protection de `/proc/*/mem` (nécessite `hidepid=2` sur /proc, ou restriction d'accès)
- Zeroize de la clé de session immédiatement après utilisation (déjà prévu)

**Vraisemblance** : **V3 Très vraisemblable** (accès root + fenêtre temporelle)

**Gravité** : **G3 GRAVE** (déchiffrement d'un bundle spécifique, pas de la KEK)

---

#### SO4 : Abaissement de l'anti-rollback via fichier (SR3 → BS6)

**Enchaînement d'actions** :
1. **SR3** extrait la flash (dessoudage ou lecteur SD)
2. **SR3** modifie le fichier de compteur anti-rollback sur la flash
3. **SR3** réinsère la flash et redémarre le device
4. **BS1** (updated) lit le compteur fichier (modifié) et le compare au compteur TPM
5. **BS1** détecte l'incohérence et rejette la mise à jour

**Mitigations existantes** :
- Compteur NV TPM comme source principale
- Fichier comme backup uniquement
- Vérification croisée (TPM > fichier)

**Mitigations manquantes** :
- Aucune (mitigations complètes)

**Vraisemblance** : **V1 Peu vraisemblable**

**Gravité** : **G3 GRAVE** (si réussi → ER6 : rollback vers version vulnérable)

---

#### SO5 : Réinitialisation TPM pour effacer la KEK (SR3 → BS3)

**Enchaînement d'actions** :
1. **SR3** accède physiquement au TPM (dessoudage ou jumper)
2. **SR3** envoie la commande `TPM2_Clear` pour réinitialiser le TPM
3. **BS3** (TPM) efface toutes les clés, y compris la KEK
4. **SR3** réinsère le TPM et redémarre le device
5. **BS1** (updated) tente de déchiffrer un bundle, échoue (KEK absente)
6. **Device bloqué** (pas de mise à jour possible)

**Mitigations existantes** :
- Détection de réinitialisation TPM (vérification que la KEK existe)
- Invalidation du device si TPM réinitialisé (bloquer les mises à jour)

**Mitigations manquantes** :
- Protection physique du TPM (potting, anti-tamper)
- Certificat d'attestation pour prouver l'identité du TPM

**Vraisemblance** : **V2 Vraisemblable** (accès physique requis)

**Gravité** : **G3 GRAVE** (device bloqué, nécessité de reprogrammation)

---

### 4.3 Synthèse des scénarios opérationnels

| Scénario | BS concernés | Vraisemblance | Gravité | Risque | Priorité |
|---|---|---|---|---|---|
| SO1 (parser bug) | BS1, BS2 | V2 | G4 | ÉLEVÉ | 🔴 Haute |
| SO2 (symlink évasion) | BS5 | V1 | G3 | FAIBLE | 🟢 Basse |
| SO3 (extraction session key) | BS4 | V3 | G3 | ÉLEVÉ | 🔴 Haute |
| SO4 (anti-rollback fichier) | BS6 | V1 | G3 | FAIBLE | 🟢 Basse |
| SO5 (réinitialisation TPM) | BS3 | V2 | G3 | MOYEN | 🟠 Moyenne |

---

## Atelier 5 : Traitement du risque

### 5.1 Synthèse des risques

| Risque | Gravité | Vraisemblance | Niveau de risque | Acceptabilité |
|---|---|---|---|---|
| R1 : Compromission supervisor via parser bug | G4 | V2 | **ÉLEVÉ** | ❌ Inacceptable |
| R2 : Extraction clé de session via /proc | G3 | V3 | **ÉLEVÉ** | ❌ Inacceptable |
| R3 : Attaque physique flash (sans chaîne de boot) | G4 | V2 | **MOYEN** | ⚠️ Tolérable (sous conditions) |
| R4 : Évasion du jail | G4 | V2 | **MOYEN** | ⚠️ Tolérable (sous conditions) |
| R5 : Réinitialisation TPM | G3 | V2 | **MOYEN** | ⚠️ Tolérable (sous conditions) |
| R6 : Attaque réseau | G4 | V1 | **FAIBLE** | ✅ Acceptable |
| R7 : Abaissement anti-rollback (fichier) | G3 | V1 | **FAIBLE** | ✅ Acceptable |
| R8 : Extraction KEK via bus TPM | G4 | V1 | **FAIBLE** | ✅ Acceptable |

### 5.2 Stratégie de traitement

#### R1 : Compromission supervisor via parser bug (ÉLEVÉ → FAIBLE)

**Stratégie** : **Réduction** (mitigations techniques)

**Mesures à implémenter** :
1. ✅ **Architecture supervisor/worker** (déjà prévue) : isolation du parsing
2. ✅ **Worker sandboxé** (déjà prévu) : pas d'accès TPM, pas d'accès MTD
3. ✅ **IPC minimal** (déjà prévu) : validated IR uniquement
4. 🔲 **Seccomp sur le supervisor** (à implémenter) : limiter les syscalls
5. 🔲 **Chaîne de boot complète** (à spécifier) : vérification du binaire `updated` au boot
6. 🔲 **Fuzzing du parser** (à implémenter) : détection de bugs avant déploiement
7. 🔲 **Audit formel du code critique** (nice-to-have) : Prusti, Kani

**Risque résiduel après traitement** : **FAIBLE**

---

#### R2 : Extraction clé de session via /proc (ÉLEVÉ → FAIBLE)

**Stratégie** : **Réduction** (mitigations techniques)

**Mesures à implémenter** :
1. ✅ **mlockall** (déjà prévu) : empêche le swap
2. ✅ **prctl(PR_SET_DUMPABLE, 0)** (déjà prévu) : empêche les core dumps
3. ✅ **Zeroize de la clé** (déjà prévu) : effacement immédiat après utilisation
4. 🔲 **hidepid=2 sur /proc** (à implémenter) : masque les processus des autres users
5. 🔲 **Restriction d'accès à /proc/*/mem** (à implémenter) : LSM (SELinux, AppArmor)
6. 🔲 **Fenêtre temporelle minimale** (à optimiser) : déchiffrement juste-avant-utilisation

**Risque résiduel après traitement** : **FAIBLE**

---

#### R3 : Attaque physique flash sans chaîne de boot (MOYEN → FAIBLE)

**Stratégie** : **Réduction** (mitigations techniques)

**Mesures à implémenter** :
1. 🔲 **Chaîne de boot complète** (à spécifier) : ROM → bootloader → kernel → `updated`
2. 🔲 **Secure boot SoC** (à choisir) : U-Boot avec signature vérification
3. 🔲 **Mesures dans PCRs TPM** (à spécifier) : bootloader, kernel, rootfs
4. 🔲 **Vérification de signature au boot** (à implémenter) : U-Boot vérifie kernel et rootfs

**Risque résiduel après traitement** : **FAIBLE**

---

#### R4 : Évasion du jail (MOYEN → FAIBLE)

**Stratégie** : **Réduction** (mitigations techniques)

**Mesures déjà spécifiées** :
1. ✅ **Namespaces** (mount, ipc, uts, cgroup, net)
2. ✅ **Seccomp** (strict, default, custom)
3. ✅ **Capabilities réduites** (drop de toutes les caps non nécessaires)
4. ✅ **Securebits stricts** (SECBIT_NOROOT, etc.)
5. ✅ **MS_NOSYMFOLLOW** sur bind mounts
6. ✅ **openat2() + RESOLVE_*** (anti-TOCTOU)
7. ✅ **Policy machine indépendante** (validation des capacités)
8. ✅ **Whitelist de device nodes**
9. ✅ **API de sortie contrôlée** (remplacement de host_bind_back)

**Mesures à implémenter** :
1. 🔲 **CLONE_NEWUSER conditionnel** (à décider) : isolation des UIDs
2. 🔲 **CLONE_NEWPID obligatoire** (à décider) : isolation des processus
3. 🔲 **Cgroups v2** (à implémenter) : limites de ressources (PID, mémoire, CPU, I/O)

**Risque résiduel après traitement** : **FAIBLE**

---

#### R5 : Réinitialisation TPM (MOYEN → FAIBLE)

**Stratégie** : **Réduction** (mitigations techniques) + **Acceptation** (risque résiduel)

**Mesures à implémenter** :
1. ✅ **Détection de réinitialisation** (déjà prévue) : vérification que la KEK existe
2. ✅ **Invalidation du device** (déjà prévue) : bloquer les mises à jour si TPM réinitialisé
3. 🔲 **Certificat d'attestation** (à implémenter) : TPM2_Quote pour prouver l'identité du TPM
4. 🔲 **Protection physique** (nice-to-have) : potting, anti-tamper

**Risque résiduel après traitement** : **FAIBLE** (device bloqué, nécessité d'intervention physique)

---

### 5.3 Plan d'amélioration continue

#### Priorité 1 : Critique (avant implémentation)

| Action | Responsable | Échéance | Statut |
|---|---|---|---|
| Spécifier la chaîne de boot complète (ROM → bootloader → kernel → `updated`) | Architecte | T+2 semaines | 🔲 À faire |
| Choisir le bootloader (U-Boot) et le mécanisme de secure boot | Architecte | T+2 semaines | 🔲 À faire |
| Spécifier les mesures PCR (bootloader, kernel, rootfs) | Architecte | T+2 semaines | 🔲 À faire |
| Décider de CLONE_NEWUSER et CLONE_NEWPID | Architecte | T+1 semaine | 🔲 À faire |
| Créer `rust-toolchain.toml` avec version stable | Dev lead | T+1 semaine | ✅ Fait (canal `stable`) |

#### Priorité 2 : Haute (pendant implémentation)

| Action | Responsable | Échéance | Statut |
|---|---|---|---|
| Implémenter seccomp sur le supervisor | Dev | T+4 semaines | 🔲 À faire |
| Implémenter hidepid=2 sur /proc | Dev | T+4 semaines | 🔲 À faire |
| Implémenter cgroups v2 pour le jail | Dev | T+4 semaines | 🔲 À faire |
| Fuzzing du parser manifeste | QA | T+6 semaines | 🔲 À faire |
| Fuzzing du parser chunks | QA | T+6 semaines | 🔲 À faire |

#### Priorité 3 : Moyenne (après MVP)

| Action | Responsable | Échéance | Statut |
|---|---|---|---|
| Implémenter TPM2_Quote (attestation distante) | Dev | T+12 semaines | 🔲 À faire |
| Implémenter la rotation des clés (KEK, signature) | Dev | T+12 semaines | 🔲 À faire |
| Audit formel du code critique (Prusti, Kani) | Dev | T+24 semaines | 🔲 À faire |
| Certification Common Criteria ou ANSSI CSPN | Dev lead | T+52 semaines | 🔲 À faire |

### 5.4 Cadre de suivi des risques

#### Indicateurs de risque

| Indicateur | Fréquence | Seuil d'alerte | Action |
|---|---|---|---|
| Nombre de CVE kernel affectant le device | Hebdomadaire | CVE critique | Mise à jour kernel urgente |
| Nombre de tentatives de mise à jour échouées | Quotidienne | > 5 échecs consécutifs | Investigation (attaque par exhaustion TPM ?) |
| Temps de vérification du header | Quotidienne | Variance > 2σ | Investigation (timing attack ?) |
| Nombre de devices avec TPM réinitialisé | Mensuelle | > 1% de la flotte | Investigation (attaque physique coordonnée ?) |
| Nombre de vulnérabilités découvertes dans le code | Mensuelle | CVE critique | Patch urgent |

#### Revue de risque

- **Revue trimestrielle** : analyse des indicateurs, mise à jour de l'analyse EBIOS RM
- **Revue annuelle** : audit complet de sécurité, test de pénétration, mise à jour du plan d'amélioration

---

## Annexes

### Annexe A : Glossaire EBIOS RM

- **Mission** : fonction, finalité, raison d'être de l'objet de l'étude
- **Valeur métier** : composante importante pour l'organisation dans l'accomplissement de sa mission
- **Événement redouté** : atteinte préjudiciable à une valeur métier
- **Source de risque** : élément susceptible d'engendrer un risque
- **Objectif visé** : but de haut niveau d'une source de risque
- **Scénario stratégique** : chemin d'attaque de haut niveau
- **Scénario opérationnel** : enchaînement d'actions techniques élémentaires
- **Bien support** : composant technique de l'objet étudié
- **Gravité** : estimation de l'intensité des effets d'un risque
- **Vraisemblance** : probabilité qu'un scénario se réalise

### Annexe B : Échelles de cotation

#### Gravité

| Niveau | Description |
|---|---|
| G4 CRITIQUE | Incapacité d'assurer l'activité, survie menacée |
| G3 GRAVE | Forte dégradation, mode très dégradé |
| G2 SIGNIFICATIVE | Dégradation, mode dégradé |
| G1 MINEURE | Aucun impact opérationnel |

#### Vraisemblance

| Niveau | Description |
|---|---|
| V4 Quasi certain | La source va certainement atteindre son objectif |
| V3 Très vraisemblable | La source va probablement atteindre son objectif |
| V2 Vraisemblable | La source est susceptible d'atteindre son objectif |
| V1 Peu vraisemblable | La source a peu de chance d'atteindre son objectif |

### Annexe C : Références

[[1]] ANSSI, "La méthode EBIOS Risk Manager - Le guide", version 1.5, mars 2024. Disponible sur : https://messervices.cyber.gouv.fr/guides/la-methode-ebios-risk-manager-le-guide

[[2]] ANSSI, "Guide des mécanismes cryptographiques", version 3.00, 2026.

[[3]] ANSSI, "Guide de développement sécurisé en Rust", 2024. Disponible sur : https://anssi-fr.github.io/rust-guide/

[[4]] Trusted Computing Group, "TPM 2.0 Library Specification", version 1.59, 2019 (la plateforme cible implémente la révision 1.38).

[[5]] MITRE, "ATT&CK Framework", 2024. Disponible sur : https://attack.mitre.org/

---

**Prochaine itération** : Après implémentation des mesures de Priorité 1 et 2, réévaluation des risques résiduels et mise à jour de l'analyse EBIOS RM.
