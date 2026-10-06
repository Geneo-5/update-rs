# Analyse EBIOS Risk Manager — update-rs

Statut : Brouillon (deuxième itération)

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
| **ER10** | Maintien prolongé sur une version vulnérable (mises à jour bloquées ou retardées sans que le device le sache) | VM1, VM3 | **G3 GRAVE** | Exploitation de vulnérabilités corrigées en amont, flotte exposée sans signal d'alerte |
| **ER11** | Compromission durable de la confiance éditeur (clé de signature ou KEK volée, sans moyen de révocation) | VM1, VM2 | **G4 CRITIQUE** | L'attaquant peut produire des bundles acceptés par toute la flotte ; remise en état nécessitant une intervention sur chaque device |

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
| **Pas de révocation de clé** | Aucun mécanisme pour révoquer ou faire tourner la clé de vérification ECC ou la KEK une fois compromises | Compromission éditeur durable (SS6, ER11) |
| **Pas de fraîcheur des mises à jour** | Ni expiration ni horodatage : un device peut être maintenu sur une version ancienne sans le savoir | Attaque freeze (SS8, ER10) |
| **Chaîne d'approvisionnement non maîtrisée** | Pas de build reproductible, de SBOM ni de signature des artefacts de build ; audit des dépendances prévu (REQ-CRY-2) mais non en place | SS7 |
| **TPM utilisable comme oracle** | La policy de la KEK autorise un digest de policy signé, pas un header donné (`03-tpm.md`, question 13) | Un détenteur de device peut utiliser son TPM pour déballer la clé de session de bundles de la flotte (SS13) |
| **Canal de contrôle local non spécifié** | Le protocole `updatectl` ↔ `updated` (authentification, droits, entrées acceptées) n'est pas décrit | SO11 |
| **Protocole de commit non défini** | L'ordre écriture du slot / vérification / incrément du compteur NV (REQ-TPM-3) n'est pas spécifié de bout en bout | SO8 |

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
| **SR9** | Propriétaire ou opérateur du device (malveillant) | Extraire le contenu des bundles, contourner les restrictions de l'éditeur, redistribuer | Moyennes (device légitime, accès root, bundles publics) | Moyennes à élevées (administration système, tpm2-tools) |
| **SR10** | Attaquant sur la chaîne d'approvisionnement logicielle (dépendances, build, CI) | Introduire du code malveillant en amont, avant signature | Élevées (compte mainteneur, CI, dépôt de paquets) | Élevées (ingénierie logicielle, social engineering) |

### 2.2 Objectifs visés par les sources de risque

| OV | Objectif visé | SR concernées |
|---|---|---|
| **OV1** | Installer un firmware malveillant (backdoor, botnet) | SR1, SR3, SR5, SR6, SR8, SR10 |
| **OV2** | Divulguer le contenu d'un bundle (propriété intellectuelle, secrets) | SR2, SR3, SR4, SR8, SR9 |
| **OV3** | Bricker le device (déni de service) | SR1, SR3, SR5, SR7 |
| **OV4** | Abaisser le compteur anti-rollback (exploiter vulnérabilités connues) | SR3, SR5, SR8 |
| **OV5** | Échapper au jail et compromettre l'hôte | SR7 |
| **OV6** | Extraire la KEK (déchiffrer tous les bundles) | SR4, SR5, SR8 |
| **OV7** | Supprimer les logs (masquer une compromission) | SR5, SR7 |
| **OV8** | Divulguer la configuration hôte (credentials, secrets locaux) | SR3, SR5, SR7, SR8 |
| **OV9** | Maintenir des devices sur une version vulnérable (bloquer ou retarder les correctifs) | SR1, SR5, SR8 |
| **OV10** | Usurper l'état de la plateforme pour faire valider une policy du TPM | SR3, SR4 |

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
| **SR6/OV1** | Éditeur (ou sa clé) signe un bundle malveillant | 🟠 Moyenne (voir SS6 : l'organisation des clés est hors périmètre, mais l'absence de révocation est dans le projet) |
| **SR8/* ** | APT (tous objectifs) | 🟡 Faible (hors périmètre actuel, défense en profondeur) |
| **SR10/OV1** | Supply chain logicielle installe un firmware malveillant | 🔴 Haute |
| **SR1/OV9** | Freeze ou downgrade pour maintenir une version vulnérable | 🟠 Moyenne |
| **SR1/OV3, SR5/OV3, SR7/OV3** | Déni de service ou brick (coupure, saturation, canal de contrôle) | 🟠 Moyenne |
| **SR4/OV10** | Reset du TPM et rejeu des mesures de plateforme | 🟠 Moyenne |
| **SR9/OV2** | Propriétaire du device divulgue le contenu d'un bundle | 🟠 Moyenne |
| **SR7/OV7** | Payload sature ou falsifie les logs | 🟡 Faible |
| **SR3/OV1 (fautes)** | Injection de fautes sur le SoC pour contourner la vérification | 🟡 Faible (hypothèses matérielles, 1.6) |

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

#### SS6 : Compromission de la clé de signature éditeur (SR6, SR8 → OV1)

**Chemin d'attaque** :
```
SR6/SR8 (accès à la clé privée de signature ECDSA P-256)
  │
  ├─▶ Signe un header et un manifeste malveillants
  │   │
  │   └─▶ TPM2_VerifySignature réussit : la signature est valide
  │
  ├─▶ Doit aussi fournir un wrapped_session_key que le device sait déballer
  │   │
  │   ├─▶ Soit en le produisant avec la KEK (symétrique, détenue côté éditeur) : stockée à part de la
  │   │   clé de signature, la compromission de la seule clé de signature ne suffit pas
  │   └─▶ Soit en réutilisant le wrapped_session_key d'un bundle existant dont il connaît la clé de
  │       session, obtenue en utilisant un device comme oracle (SS13, SO16)
  │
  ├─▶ Incrémente bundle_version pour passer l'anti-rollback
  │
  └─▶ Aucune révocation : la clé de vérification est fixe à vie du dispositif (écart 1.7)
```

Si la KEK est commune à toute la flotte et stockée avec la clé de signature, un seul vol compromet tous les devices. Tant que le TPM peut servir d'oracle (SS13), la séparation entre clé de signature et KEK n'apporte pas de protection réelle.

**Gravité** : **G4 CRITIQUE** (ER1, ER11)

**Vraisemblance** : **V2 Vraisemblable** (la clé est une cible de choix ; l'organisation des clés est hors périmètre, mais l'absence de révocation est dans le projet)

**Risque résiduel** : **ÉLEVÉ**

---

#### SS7 : Compromission de la chaîne d'approvisionnement logicielle (SR10 → OV1)

**Chemin d'attaque** :
```
SR10 (compte mainteneur, dépôt de paquets, CI, toolchain de cross-compilation)
  │
  ├─▶ Publie une version malveillante d'une dépendance (crypto, TPM, parsing)
  │   │
  │   └─▶ Cargo.lock versionné, cargo audit/vet/deny (REQ-CRY-2) : prévus, pas en place
  │
  ├─▶ Modifie `updated` ou `bundle-tool` pendant le build
  │   │
  │   └─▶ Pas de build reproductible ni de signature des artefacts : non détecté
  │
  └─▶ Un `updated` piégé court-circuite les vérifications logicielles, ou un `bundle-tool` piégé
      signe/chiffre autre chose que ce qui a été validé
      │
      └─▶ Seule la chaîne de boot vérifiée (non spécifiée) détecterait un `updated` modifié
```

La TCB inclut des composants C (`tpm2-tss` via `tss-esapi`, toolchain `gcc-arm-linux-gnueabihf`) en plus des crates Rust.

**Gravité** : **G4 CRITIQUE** (ER1)

**Vraisemblance** : **V2 Vraisemblable**

**Risque résiduel** : **ÉLEVÉ**

---

#### SS8 : Downgrade et freeze (SR1, SR5, SR8 → OV4, OV9)

**Chemin d'attaque** :
```
SR1/SR5/SR8 (réseau, serveur de distribution compromis, ou accès local)
  │
  ├─▶ Downgrade : rejoue un ancien bundle valablement signé
  │   │
  │   └─▶ Rejeté si bundle_version ≤ compteur NV (REQ-TPM-3) ou min_firmware_version non satisfait
  │
  ├─▶ Freeze : bloque ou ralentit la distribution, ne sert que des bundles déjà installés
  │   │
  │   └─▶ Aucune expiration ni horodatage : le device reste indéfiniment sur une version
  │       vulnérable sans le savoir (écart 1.7)
  │
  └─▶ Mix-and-match de composants (noyau d'une version, rootfs d'une autre)
      │
      └─▶ Couvert seulement si un bundle porte un jeu cohérent d'images (question ouverte 3 de `02`)
```

**Gravité** : **G3 GRAVE** (ER6, ER10)

**Vraisemblance** : **V3 Très vraisemblable** (le freeze ne demande qu'un contrôle du transport, et rien ne le détecte)

**Risque résiduel** : **ÉLEVÉ** (le downgrade est traité, le freeze ne l'est pas)

---

#### SS9 : Déni de service et brick (SR1, SR5, SR7 → OV3)

**Chemin d'attaque** :
```
SR1/SR5/SR7
  │
  ├─▶ Coupe l'alimentation ou le réseau pendant l'écriture du slot
  │   │
  │   └─▶ Slot corrompu ; l'A/B est spécifié (REQ-FLW-1 à 3) mais non intégré à la machine à états
  │
  ├─▶ Sature le stockage ou la RAM (tmpfs du jail, bundle volumineux)
  │   │
  │   └─▶ Limites cgroups et bornes mémoire (REQ-BUN-5 ; cgroups dans `06-jail.md`), spécifiées
  │
  ├─▶ Inonde le service de requêtes (TPM, canal de contrôle local)
  │   │
  │   └─▶ Rate limiting et backoff (A11 dans `07`), spécifiés ; canal de contrôle non spécifié
  │
  └─▶ Bundle authentique mais défectueux (erreur de l'éditeur) installé sur toute la flotte
      │
      └─▶ Ni health-check ni rollback automatique spécifiés de bout en bout
```

**Gravité** : **G3 GRAVE** (ER3, ER8)

**Vraisemblance** : **V3 Très vraisemblable** (en l'absence d'A/B et de protocole de commit)

**Risque résiduel** : **ÉLEVÉ**

---

#### SS10 : Exfiltration de la configuration hôte par le payload (SR7 → OV8)

**Chemin d'attaque** :
```
SR7 (payload dans le jail)
  │
  ├─▶ Lit des fichiers hôte via un bind mount
  │   │
  │   └─▶ Policy machine (whitelist), lecture seule, MS_NOSYMFOLLOW, openat2 (SS4, SO2)
  │
  ├─▶ Exfiltre par le réseau
  │   │
  │   └─▶ CLONE_NEWNET : réseau toujours isolé
  │
  ├─▶ Exfiltre par l'API de sortie contrôlée (logs) ou le code retour
  │   │
  │   └─▶ Capture par le superviseur (REQ-JAIL-10) ; taille et format de la sortie non bornés
  │
  └─▶ Écrit des données hôte dans le slot ou la partition cible, lues plus tard par un attaquant physique
      │
      └─▶ Non traité : le contenu écrit par le payload n'est pas contrôlé par le superviseur
```

**Gravité** : **G3 GRAVE** (ER9)

**Vraisemblance** : **V2 Vraisemblable**

**Risque résiduel** : **MOYEN**

---

#### SS11 : Usurpation de l'état de plateforme par reset du TPM (SR4, SR3 → OV10, OV2)

**Chemin d'attaque** :
```
SR4/SR3 (accès physique au TPM : bus SPI et ligne de reset)
  │
  ├─▶ Réinitialise le TPM sans redémarrer le SoC
  │
  ├─▶ Rejoue des extensions de PCR correspondant à un boot sain (mesures enregistrées avant)
  │   │
  │   └─▶ Satisfait un PolicyPCR : toute protection reposant sur les seuls PCR est défaite
  │
  └─▶ Demande le déballage de wrapped_session_key avec la signature de policy lue sur le device
      │
      └─▶ PolicyAuthorize ne protège pas ici : la signature de policy n'est pas un secret (elle est
          fournie au TPM à chaque mise à jour) ; seul l'état des PCR s'oppose à la demande
```

**Gravité** : **G3 GRAVE** (ER2 ; la KEK reste dans le TPM, mais la clé de session d'un bundle est livrée)

**Vraisemblance** : **V2 Vraisemblable** (accès physique requis, attaque documentée sur les TPM discrets)

**Risque résiduel** : **MOYEN**

---

#### SS12 : Injection de fautes sur le SoC (SR8, SR3 → OV1, OV6)

**Chemin d'attaque** :
```
SR8/SR3 (glitching tension/horloge, injection de fautes électromagnétique)
  │
  ├─▶ Saute la vérification de signature du bootloader (secure boot SoC)
  │   │
  │   └─▶ Hypothèse matérielle (1.6), hors périmètre de `update-rs`
  │
  ├─▶ Saute un test logiciel dans `updated` (résultat de la vérification de signature)
  │   │
  │   └─▶ Le déballage reste conditionné par la policy du TPM, mais la vérification du header est
  │       séquencée par le logiciel (question 13 de `03`) : un header non authentique peut être présenté
  │
  └─▶ Extrait des secrets du TPM par fautes ou canaux auxiliaires
      │
      └─▶ Hors périmètre (certification du composant)
```

**Gravité** : **G4 CRITIQUE** (ER1, ER7)

**Vraisemblance** : **V1 Peu vraisemblable** (équipement et compétences élevés, accès physique)

**Risque résiduel** : **FAIBLE** (accepté au titre des hypothèses matérielles)

---

#### SS13 : Divulgation du contenu par le propriétaire du device (SR9, SR2 → OV2)

**Chemin d'attaque** :
```
SR9 (propriétaire ou opérateur, root sur un device légitime)
  │
  ├─▶ Exécute `updated` avec un bundle légitime
  │   │
  │   ├─▶ Lit la clé de session en RAM (SO3)
  │   └─▶ Lit le payload extrait ou le contenu du tmpfs du jail (root sur l'hôte)
  │
  ├─▶ Utilise son TPM comme oracle de déchiffrement pour d'autres bundles de la même KEK
  │   │
  │   └─▶ Possible tant que la policy n'est pas liée au header (question 13 de `03`)
  │
  └─▶ Redistribue le contenu
```

Limite du modèle : la confidentialité est opposable aux attaquants sans device légitime (A1 à A4), pas à celui qui contrôle le device. Avec une KEK commune à la flotte, un seul device ouvre tous les bundles de la flotte ; une KEK par device ou par famille (question 6 de `00`) limiterait l'exposition. La clé de session étant unique par bundle, l'extraction de l'une d'elles n'expose que ce bundle.

**Gravité** : **G3 GRAVE** (ER2)

**Vraisemblance** : **V4 Quasi certain** (pour qui contrôle un device)

**Risque résiduel** : **ÉLEVÉ** (arbitrage requis, voir R16)

---

#### SS14 : Erreur de provisionnement — KEK incorrecte chargée (SR10 → OV7)

**Chemin d'attaque** :
```
SR10 (fabricant ou intégrateur)
  │
  ├─▶ Charge une KEK incorrecte dans le TPM de N devices
  │   │
  │   └─▶ Les bundles signés par l'éditeur ne correspondent à aucune KEK de ces devices
  │
  ├─▶ Ou : re-provisionne un device en campo avec une nouvelle KEK sans bundle de migration
  │   │
  │   └─▶ Le device devient intrinsèquement inamisable (aucun futur bundle ne contient le nouveau kek_id)
  │
  └─▶ Résultat : device ou lot de devices incapables de recevoir DES mises à jour
```

**Gravité** : **G4 CRITIQUE** (ER3 — device brické par erreur de gestion)

**Vraisemblance** : **V4 Quasi certain** (inévitable à échelle de production : erreurs humaines, processus dégradés, re-provisionnement sans bundle de migration)

**Risque résiduel** : **ÉLEVÉ**

---

#### SS15 : Compromission flotte-wide par KEK unique (SR8, SR9 → OV2)

**Chemin d'attaque** :
```
SR8 ou SR9 (compromission d'un device ou du poste de build)
  │
  ├─▶ Extrait la KEK d'un device (SO16, SO18, ou reverse-engineering)
  │
  └─▶ Si la flotte utilise une KEK unique ou par famille :
      │
      ├─▶ Récupère N bundles de la flotte (stockés sur le serveur ou capturés)
      │
      └─▶ Déchiffre L'INTÉGRALITÉ des bundles de la flotte qui partagent cette KEK
```

Limite du modèle : la confidentialité n'est opposable qu'aux attaquants sans device légitime. Avec une KEK unique par flotte, un seul device ouvre tous les bundles de la flotte. Avec une KEK par famille, un lot de devices du même modèle.

**Gravité** : **G4 CRITIQUE** (toute la flotte déchiffrée)

**Vraisemblance** : **V3 Très vraisemblable** (si la flotte utilise une KEK unique ou par famille)

**Risque résiduel** : **ÉLEVÉ**

---

#### SS16 : Re-provisionnement d'un device capturé (SR9 → OV2)

**Chemin d'attaque** :
```
SR9 (capture d'un device physique)
  │
  ├─▶ Extrait la KEK du device capturé (SO16 ou SO18)
  │
  ├─▶ Le device est re-provisionné (changement de politique, migration de flotte, remplacement hardware)
  │   │
  │   └─▶ Une nouvelle KEK est chargée ; l'ancienne est rendue inopérante (ou présente dans un pool)
  │
  ├─▶ SR9 utilise l'ancienne KEK pour déchiffrer des bundles capturés (ancien kek_id)
  │   │
  │   └─▶ Si le device re-provisionné contient l'ancienne KEK (pool), SR9 peut installer
  │       rétroactivement d'anciens bundles capturés
  │
  └─▶ Ou : SR9 installe un bundle capturé (ancien kek_id) sur un device B qui partage
      l'ancienne KEK de A (cross-device)
```

**Gravité** : **G3 GRAVE** (déchiffrement de bundles capturés, risque cross-device)

**Vraisemblance** : **V3 Très vraisemblable** (si les bundles capturés avant re-provisionnement circulent encore sur le réseau)

**Risque résiduel** : **ÉLEVÉ**

---

### 3.3 Synthèse des scénarios stratégiques

| Scénario | Gravité | Vraisemblance | Risque résiduel | Priorité |
|---|---|---|---|---|
| SS1 (réseau) | G4 | V1 | FAIBLE | 🟢 Basse |
| SS2 (physique flash) | G4 | V2 | MOYEN | 🟠 Moyenne |
| SS3 (local root) | G4 | V3 | ÉLEVÉ | 🔴 Haute |
| SS4 (évasion jail) | G4 | V2 | MOYEN | 🟠 Moyenne |
| SS5 (bus TPM) | G4 | V1 | FAIBLE | 🟢 Basse |
| SS6 (clé de signature éditeur) | G4 | V2 | ÉLEVÉ | 🔴 Haute |
| SS7 (supply chain) | G4 | V2 | ÉLEVÉ | 🔴 Haute |
| SS8 (downgrade / freeze) | G3 | V3 | ÉLEVÉ | 🔴 Haute |
| SS9 (DoS / brick) | G3 | V3 | ÉLEVÉ | 🔴 Haute |
| SS10 (exfiltration par le payload) | G3 | V2 | MOYEN | 🟠 Moyenne |
| SS11 (reset TPM, rejeu PCR) | G3 | V2 | MOYEN | 🟠 Moyenne |
| SS12 (injection de fautes) | G4 | V1 | FAIBLE | 🟢 Basse |
| SS13 (propriétaire du device) | G3 | V4 | ÉLEVÉ | 🟠 Moyenne (arbitrage) |

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
| **BS9** | Poste de signature, CI et dépôts de dépendances | Clé privée de signature, KEK côté éditeur, build de `updated` et de `bundle-tool` | 🔴 Critique |
| **BS10** | Canal de contrôle local (`updatectl` ↔ `updated`) | Déclenchement et suivi des mises à jour | 🟠 Haute |
| **BS11** | Journalisation (journald, logs hôte) | Traçabilité (VM4), sortie du payload | 🟠 Haute |
| **BS12** | Environnement du bootloader et sélection de slot | Choix du slot booté, paramètres de boot | 🔴 Critique |

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

**Vraissemblance** : **V3 Très vraisemblable** (réévalué de V2 : le worker n'est pas isolé par un PID namespace ni par un user namespace ; un root local peut potentiellement lire `/proc/<pid>/mem` du worker, ou exploiter une vulnérabilité IPC pour monter en privilèges vers le supervisor. La fenêtre est courte mais le vecteur est documenté sur de multiples implantations. **Contre-mesure** : masquer /proc via `hidepid=2`, ou exécuter le worker dans un user namespace conditionnel (`CLONE_NEWUSER`) dès que le kernel le supporte sur l'architecture cible.)

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

**Vraissemblance** : **V3 Très vraisemblable** (réévalué de V1 : un attaquant avec accès physique à la flash (dessoudage) contrôle déjà le système et peut modifier librement le compteur. Sans accès physique, un root local peut écrire sur le device character du TPM NV index (`/dev/tpm0` ou `/dev/tpmrm0`) si les permissions ne sont pas strictement restreintes (owner-only, 0600) ; les fichiers de compteur de backup sur la partition système sont accessibles via les bind mounts jail→hôte si les règles fsset sont mal configurées. Contre-mesure : permissions 0600 sur le device NV TPM, lecture/écriture du compteur protégée par vérification PCR croisée, backup sur partition séparée signée, monitoring des accès TPM par audit kernel.)

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

#### SO6 : Reset du TPM et rejeu des PCR (SR4 → BS3, BS7) — SS11

**Enchaînement d'actions** :
1. **SR4** accède physiquement à la ligne de reset du TPM et au bus SPI
2. **SR4** enregistre les extensions de PCR d'un boot sain (bus SPI)
3. **SR4** modifie le bootloader ou le kernel, redémarre, puis réinitialise le TPM sans réinitialiser le SoC
4. **SR4** rejoue les extensions de PCR enregistrées : les PCR affichent un état sain
5. **BS3** (TPM) voit un état de PCR conforme ; **SR4** présente la signature de policy lue sur le device et demande le déballage de la clé de session d'un bundle capturé

**Mitigations existantes** :
- Aucune mitigation efficace dans la spécification actuelle : `PolicyAuthorize` repose sur une signature de policy non secrète, et `PolicyPCR` est optionnelle
- Sessions chiffrées TPM : sans effet, l'attaquant parle au TPM par son propre canal

**Mitigations manquantes** :
- `PolicyPCR` obligatoire (optionnelle dans `03-tpm.md`)
- Ligne de reset du TPM reliée au reset du SoC (matériel)
- Lier la policy au header (question 13 de `03`), sinon le TPM sert d'oracle (SO16)

**Vraisemblance** : **V2 Vraisemblable**

**Gravité** : **G3 GRAVE** (ER2)

---

#### SO7 : Retour sur un ancien slot via l'environnement du bootloader (SR3, SR5 → BS12) — SS8

**Enchaînement d'actions** :
1. **SR5** (root) ou **SR3** (flash hors tension) modifie la variable de sélection de slot dans l'environnement U-Boot
2. Le device démarre sur l'ancien slot, qui contient une version vulnérable mais authentique
3. Le compteur NV du TPM, qui ne porte que sur les bundles installés, ne détecte rien
4. **SR5** exploite une vulnérabilité connue de l'ancienne version

**Mitigations existantes** :
- Compteur NV anti-rollback (bundles installés uniquement)

**Mitigations manquantes** :
- Environnement U-Boot signé, en lecture seule ou mesuré dans un PCR
- Vérification, au boot, de la version du slot démarré contre le compteur NV
- Intégration de l'A/B dans la spécification (`04-update-flow.md`)

**Vraisemblance** : **V2 Vraisemblable** (dépend du modèle A/B retenu)

**Gravité** : **G3 GRAVE** (ER6)

---

#### SO8 : Coupure d'alimentation pendant le commit (SR1, SR3 → BS1, BS6) — SS9

**Enchaînement d'actions** :
1. **BS1** valide le bundle et écrit les images dans le slot cible
2. **SR3** coupe l'alimentation pendant l'écriture MTD, ou à l'instant du commit
3. Cas A : le slot est partiellement écrit et le compteur n'est pas incrémenté → slot corrompu ; sans A/B intégré, le device peut ne plus démarrer
4. Cas B (si l'incrément précède la fin de l'écriture) : le compteur NV est incrémenté mais l'écriture est incomplète → le même bundle est ensuite rejeté par l'anti-rollback alors que le slot reste incomplet (la version est « consommée »)

**Mitigations existantes** :
- REQ-TPM-3 : incrément du compteur seulement après validation (commit)
- A/B spécifié (REQ-FLW-1 à 3)

**Mitigations manquantes** :
- Protocole de commit atomique défini de bout en bout (écriture, relecture et vérification, bascule du slot, incrément du compteur) avec reprise après coupure
- Health-check et watchdog au premier boot du nouveau slot

**Vraisemblance** : **V3 Très vraisemblable** (coupure accidentelle comprise)

**Gravité** : **G3 GRAVE** (ER3)

---

#### SO9 : Header ou manifeste hostile avant authentification (SR1 → BS1, BS2) — SS9

**Enchaînement d'actions** :
1. **SR1** sert un fichier dont le header (512 octets, non authentifié à ce stade) porte `chunk_count` ou `chunk_size` extrêmes
2. **BS1** lit le header ; une implémentation qui dimensionne un buffer ou une boucle sur ces valeurs avant la vérification TPM épuise la RAM ou le CPU
3. Variante : un bundle authentique d'un éditeur compromis (SS6) porte un manifeste de taille démesurée, tamponné en entier avant vérification du tag

**Mitigations existantes** :
- Ordre de validation de `02` : les étapes 2 à 5 ne font que comparer des champs non authentifiés ; la signature est vérifiée à l'étape 7, avant tout dimensionnement fondé sur `chunk_size` ou `chunk_count`
- REQ-BUN-5 (mémoire bornée), REQ-BUN-6 (pas d'allocation pilotée par une valeur non authentifiée)

**Mitigations manquantes** :
- Bornes numériques maximales (`chunk_size`, `chunk_count`, taille du manifeste : questions 6 et 8 de `02`)
- Fuzzing du parseur de header

**Vraisemblance** : **V2 Vraisemblable**

**Gravité** : **G2 SIGNIFICATIVE** (ER8)

---

#### SO10 : Épuisement des ressources du TPM (SR5, SR1 → BS3) — SS9

**Enchaînement d'actions** :
1. **SR5** (ou **SR1** si le déclenchement est distant) lance de nombreuses tentatives de mise à jour avec des headers invalides
2. Chaque tentative ouvre des sessions et des séquences de hash dans le TPM
3. Les ressources internes du TPM (sessions chargées, séquences, mémoire) sont saturées (un verrouillage anti-bruteforce n'est à craindre que si des autorisations par `authValue` sont en jeu)
4. Les mises à jour légitimes échouent jusqu'au redémarrage ou à l'expiration du verrouillage

**Mitigations existantes** :
- Rate limiting et backoff exponentiel (A11 dans `07`)
- Vérification de magic, version et taille avant tout appel TPM (filtre faible : un header bien formé suffit à le passer)

**Mitigations manquantes** :
- Libération systématique des sessions et séquences (gestion RAII, resource manager `/dev/tpmrm0`)
- Test de saturation sur un TPM réel (nombre de sessions simultanées)

**Vraisemblance** : **V3 Très vraisemblable**

**Gravité** : **G2 SIGNIFICATIVE** (ER8)

---

#### SO11 : Abus du canal de contrôle local (SR5 → BS10) — SS9

**Enchaînement d'actions** :
1. **SR5** (compte local non privilégié) se connecte au canal d'`updated` utilisé par `updatectl`
2. **SR5** demande une mise à jour depuis un chemin ou une URL de son choix, annule une mise à jour en cours, ou en déclenche en boucle
3. Variante : le chemin fourni est un lien symbolique ou une course (TOCTOU) vers un fichier choisi par l'attaquant
4. **BS1** traite l'entrée avec les privilèges root

**Mitigations existantes** :
- `updated` s'exécute en root et traite tout bundle comme hostile (REQ-THR-7), signature obligatoire

**Mitigations manquantes** :
- Spécification du protocole de contrôle : droits du socket, vérification des identifiants du pair (`SO_PEERCRED`), liste des commandes autorisées
- Aucun chemin ou URL fourni par le client : source configurée côté serveur
- Journalisation de chaque demande

**Vraisemblance** : **V2 Vraisemblable**

**Gravité** : **G3 GRAVE**

---

#### SO12 : Saturation et falsification des logs par le payload (SR7 → BS11) — SS10

**Enchaînement d'actions** :
1. **SR7** (payload) écrit un volume énorme sur stdout/stderr, ou des lignes imitant des événements du superviseur (succès de vérification, fin de mise à jour)
2. **BS11** journalise la sortie captée (REQ-JAIL-10) ; la rotation des logs écrase les événements précédents
3. Les traces d'une compromission antérieure (ER4) sont perdues ou noyées
4. Variante : la sortie sert de canal d'exfiltration (SS10)

**Mitigations existantes** :
- Sortie capturée par le superviseur ; limites cgroups (CPU, mémoire, I/O)

**Mitigations manquantes** :
- Quota de sortie par exécution, préfixe ou champ structuré non falsifiable distinguant les événements du superviseur
- Journal des événements critiques séparé de la sortie du payload, avec extension d'un PCR (`07` § 4.2)

**Vraisemblance** : **V3 Très vraisemblable**

**Gravité** : **G2 SIGNIFICATIVE** (ER4)

---

#### SO13 : Dépendance malveillante dans le build (SR10 → BS9) — SS7

**Enchaînement d'actions** :
1. **SR10** prend le contrôle du compte d'un mainteneur d'une crate utilisée (crypto, TPM, parsing) et publie une version piégée
2. Un `cargo update`, ou la résolution d'une dépendance transitive, intègre cette version
3. La CI compile `updated` et `bundle-tool`, signés ensuite normalement par l'éditeur
4. Le code piégé s'exécute en root sur les devices, ou exfiltre des clés côté éditeur

**Mitigations existantes** :
- Versions épinglées et `Cargo.lock` versionné (REQ-CRY-2)
- Primitives issues des bibliothèques des projets de l'ANSSI (REQ-CRY-1)

**Mitigations manquantes** :
- `cargo audit`, `cargo vet` et `cargo deny` actifs en CI
- Vendoring des dépendances, revue de chaque mise à jour sur les crates critiques
- Build reproductible, SBOM, signature des artefacts de build

**Vraisemblance** : **V2 Vraisemblable**

**Gravité** : **G4 CRITIQUE**

---

#### SO14 : Vol de la clé de signature sur le poste de build (SR6, SR8 → BS9) — SS6

**Enchaînement d'actions** :
1. **SR8** compromet le poste ou la CI qui exécute `bundle-tool`
2. **SR8** exfiltre la clé privée de signature (et la KEK si elle est stockée au même endroit)
3. **SR8** produit hors ligne des bundles malveillants valides pour les devices dont il détient la KEK, ou, sans la KEK, en réutilisant un `wrapped_session_key` dont il connaît la clé de session (obtenue par SO16)
4. Sans révocation, aucune mise à jour légitime ne peut « reprendre la main » sans intervention sur chaque device

**Mitigations existantes** :
- Création des bundles hors ligne (REQ-BUN-1)
- Signatures hybrides prévues pour les artefacts internes (`05`, emplacement non spécifié : question 9 de `02`)

**Mitigations manquantes** :
- Clé de signature en HSM, cérémonie de clés, KEK stockée séparément
- Double signature ou quorum pour les releases
- Mécanisme de révocation et de rotation de la clé de vérification (NV index)
- Journal d'audit des signatures

**Vraisemblance** : **V2 Vraisemblable**

**Gravité** : **G4 CRITIQUE** (ER1, ER11)

---

#### SO15 : Réordonnancement, troncature et mélange de chunks (SR1 → BS1, BS2) — SS1

**Enchaînement d'actions** :
1. **SR1** intercepte le bundle et réordonne deux chunks, supprime le dernier, ou duplique un chunk
2. **SR1** insère un chunk issu d'un autre bundle signé pour le même device
3. **BS2** (worker) déchiffre dans l'ordre
4. Chaque modification est détectée par l'AEAD

**Mitigations existantes** :
- AAD structurée (`bundle_id`, `chunk_index`, `chunk_count`, `is_last_chunk`, `chunk_data_length`) et validation séquentielle (REQ-BUN-12 à 14)
- Clé et nonce dérivés par chunk depuis une clé de session unique par bundle : un chunk d'un autre bundle ne s'authentifie pas (REQ-BUN-15)

**Mitigations manquantes** :
- Vecteurs de test négatifs et fuzzing du lecteur de chunks

**Vraisemblance** : **V1 Peu vraisemblable**

**Gravité** : **G4 CRITIQUE** (si accepté → ER1)

---

#### SO16 : TPM utilisé comme oracle de déchiffrement (SR9 → BS3, BS4) — SS13

**Enchaînement d'actions** :
1. **SR9** (root sur un device légitime) récupère un bundle chiffré pour la même KEK, par exemple depuis le serveur de distribution
2. **SR9** envoie directement au TPM (`/dev/tpmrm0`, sans `updated`) la signature de policy déjà fournie avec le dispositif, puis `wrapped_session_key` (la commande de déballage reste à confirmer, voir l'avertissement de `03`)
3. **BS3** (TPM) satisfait la policy, car `PolicyAuthorize` n'est pas liée au header
4. **SR9** récupère la clé de session, en dérive les clés de chunk (HKDF, entrées publiques) et déchiffre le bundle hors ligne

**Mitigations existantes** :
- Clé de session unique par bundle et clés par chunk : une extraction n'expose que le bundle concerné
- Sessions chiffrées TPM (protègent contre le bus, pas contre root)

**Mitigations manquantes** :
- Lier la policy de la KEK au header ou au bundle (question 13 de `03`)
- KEK par device ou par famille (question 6 de `00`)
- Restriction d'accès à `/dev/tpmrm0` (LSM, droits), à envisager en défense en profondeur seulement (root la contourne)

**Vraisemblance** : **V4 Quasi certain** (pour qui contrôle un device)

**Gravité** : **G3 GRAVE** (ER2)

---

#### SO17 : Malfaision de provisionnement (mauvaise KEK chargée) (SR10 → BS3, BS1) — SS7

**Enchaînement d'actions** :
1. **SR10** (fabricant ou intégrateur) charge une KEK incorrecte dans le TPM de certains devices lors du provisioning en usine
2. Les bundles produits par l'éditeur ne peuvent pas être déchiffrés par ces devices (aucun `kek_id` ne correspond)
3. **BS1** (updated) échoue sur le déchiffrement de la clé de session : `KEK_NOT_FOUND` ou `POLICY_FAIL`
4. **Device définitivement incapable de recevoir des mises à jour**

**Variantes** :
- **Provisionnement partiel** : seuls certains devices d'une même campagne ont la mauvaise KEK ; l'éditeur ne peut pas savoir quelle KEK charger (plusieurs `kek_id` dans différents bundles, aucun ne correspond).
- **Provisionnement révisé** : un device est re-provisionné en campo avec une nouvelle KEK sans que les bundles suivants n'intègrent le nouveau `kek_id` ; le device devient intrinsèquement inamisable.

**Mitigations existantes** :
- Vérification post-provisionnement (`TPM2_ReadLock` + vérification que `KEK_id` match `header.kek_id`)
- Journal de provisioning côté éditeur (corrélation `kek_id` → `device_serial`)

**Mitigations manquantes** :
- Processus de vérification de provisioning : lot de test avec bundle signed, vérification qu'aucun device ne rejette
- Mécanisme de migration de KEK : un bundle « de migration » signe le nouveau `kek_id` et le charge dans le TPM (nécessite une cérémonie de clés)
- Détection en campo : un device qui rejette N bundles consécutifs peut demander au serveur quelle KEK il attend ; le serveur répond avec le bon `kek_id` (et un bundle de migration signé)
- Gestion d'un pool de KEK : un device peut contenir plusieurs KEK ; un bundle spécifie le `kek_id` cible parmi celles présentes

**Vraisemblance** : **V4 Quasi certain** (inévitable à échelle de production : erreurs humaines, processus dégradés, re-provisionnement sans mise à jour du bundle de migration)

**Gravité** : **G4 CRITIQUE** (un device ou lot de devices définitivement inutilisable, pas de mise à jour possible)

---

#### SO18 : Extraction de clé de session par forensique mémoire post-crash (SR3 → BS4)

**Enchaînement d'actions** :
1. **SR3** provoque un panic kernel (ou coupure d'alimentation) pendant que `updated` détient la clé de session en RAM
2. **SR3** extrait la RAM (bus DMA, lecture directe, ou image de sommeil/hybernation)
3. **SR3** recherche la clé de session en clair (signature brute-force sur les hashes de signature valides, ou pattern de clé AES-256)
4. **SR3** utilise la clé de session pour déchiffrer les chunks du bundle en cours d'installation

**Mitigations existantes** :
- `mlockall(MCL_CURRENT | MCL_FUTURE)` empêche le swap sur disque
- `madvise(MADV_DONTDUMP)` empêche les core dumps et images de sommeil
- `prctl(PR_SET_DUMPABLE, 0)` empêche les core dumps

**Mitigations manquantes** :
- Zeroize de la clé de session dans le signal panic (panic handler qui call `memset_s` sur la clé de session)
- Chiffrement de la RAM en repos (memory encryption, Intel TXT / ARM SME / AMU)
- Clear-on-drop de la clé de session (zeroize dans le destructeur `Drop` Rust)
- Vérification que les pages de la clé de session ne sont pas mappées dans le swap (même si `mlock` est posé)

**Vraisemblance** : **V3 Très vraisemblable** (si le panic ne zeroise pas explicitement la clé, et si la RAM n'est pas chiffrée — option matérielle non garantie sur tous les SoC ARMv7)

**Gravité** : **G3 GRAVE** (déchiffrement d'un bundle spécifique en cours d'installation)

---

#### SO19 : Compromission flotte-wide par KEK unique (SR9, SR8 → BS3, BS4, BS9) — SS6

**Enchaînement d'actions** :
1. **SR8** (ou **SR9**) compromet l'extraction d'une KEK d'un device (via SO16 ou SO18, ou par reverse-engineering du firmware)
2. La flotte utilise une **KEK unique** (ou une poignée de KEK par famille) — question 6 de `00`, question 6 de `03`
3. **SR8/SR9** récupère N bundles de la flotte (stockés sur le serveur de distribution, ou capturés par SR1)
4. **SR8/SR9** déchiffre **l'intégralité des bundles de la flotte** qui partagent cette KEK

**Mitigations existantes** :
- Clé de session unique par bundle : l'extraction d'une session key n'expose qu'un bundle
- Sessions chiffrées TPM (protègent contre le bus, pas contre root)

**Mitigations manquantes** :
- KEK **par device** (unique à chaque device, provisionnée en usine) : compromettre un device ne compromet que ce device
- Ou : KEK **par famille** (une KEK par modèle de device, pas par flotte) : compromettre un lot n'ouvre qu'un modèle
- Mécanisme de migration de KEK : un bundle « de migration » permet de charger une nouvelle KEK dans le TPM sans casser les bundles existants
- Rotation de KEK : cérémonie de clés pour passer d'une ancienne KEK à une nouvelle sans interrompre les devices en campo

**Vraisemblance** : **V3 Très vraisemblable** (si la flotte utilise une KEK unique ou par famille, ce qui est le cas par défaut si aucune politique contraire n'est appliquée)

**Gravité** : **G4 CRITIQUE** (toute la flotte déchiffrée, pas seulement un device)

---

#### SO20 : Re-provisionnement d'un device capturé (SR9 → BS3, BS4, BS1) — SS13

**Enchaînement d'actions** :
1. **SR9** capture un device physique (ou en obtient un identique) et en extrait la KEK (SO16 ou SO18)
2. **SR9** fait re-provisionner le device (ou un device identique) avec une **nouvelle KEK** (changement de politique, migration de flotte, ou remplacement hardware)
3. **SR9** utilise la **ancienne KEK** extraite pour déchiffrer des bundles signés avec l'ancien `kek_id`
4. **SR9** parvient à installer des bundles « rétroactifs » sur le device re-provisionné : le nouveau `kek_id` est dans le bundle, mais **l'ancien bundle** (capturé avant re-provisionnement) utilise l'ancien `kek_id`

**Variantes** :
- **Bundle capture post-re-provisionnement** : le device re-provisionné reçoit un bundle signé avec son nouveau `kek_id`. **SR9** a capturé l'ancien bundle (avec l'ancien `kek_id`) et tente de l'installer : le rejet est attendu. Mais si le device contient **les deux KEK** (pool de KEK), **SR9** utilise l'ancienne KEK pour déchiffrer l'ancien bundle.
- **Bundle cross-device** : **SR9** capture un bundle d'un device A, le device A est re-provisionné, et **SR9** tente d'installer le bundle capturé sur un device B qui partage l'ancienne KEK de A.

**Mitigations existantes** :
- `kek_id` dans le header : le device rejette les bundles dont le `kek_id` ne correspond pas à une KEK provisionnée
- Clé de session unique par bundle : l'extraction d'une session key n'expose qu'un bundle

**Mitigations manquantes** :
- Politique de **validité temporelle des KEK** : une KEK périmée ne doit plus pouvoir déchiffrer de nouveaux bundles (mais peut-elle déchiffrer d'anciens bundles ?)
- **Bundle de migration** : un bundle « de migration » signe le nouveau `kek_id` et le charge dans le TPM ; les anciens bundles restent valables mais ne peuvent plus être installés après migration
- **Politique de rotation** : une politique de rotation de KEK (tous les N bundles ou M années) réduit la fenêtre d'exposition d'une KEK compromise
- **Revocation list** : une liste de KEK révoquées stockée dans le TPM ; un bundle dont le `kek_id` est dans la liste est rejeté

**Vraisemblance** : **V3 Très vraisemblable** (si un dispositif est capturé, re-provisionné, et que les bundles capturés avant re-provisionnement circulent encore sur le réseau)

**Gravité** : **G3 GRAVE** (déchiffrement de bundles capturés, risque cross-device)

---

### 4.3 Synthèse des scénarios opérationnels

| Scénario | BS concernés | Vraisemblance | Gravité | Risque | Priorité |
|---|---|---|---|---|---|
| SO1 (parser bug) | BS1, BS2 | V2 | G4 | ÉLEVÉ | 🔴 Haute |
| SO2 (symlink évasion) | BS5 | V1 | G3 | FAIBLE | 🟢 Basse |
| SO3 (extraction session key) | BS4 | V3 | G3 | ÉLEVÉ | 🔴 Haute |
| SO4 (anti-rollback fichier) | BS6 | V1 | G3 | FAIBLE | 🟢 Basse |
| SO5 (réinitialisation TPM) | BS3 | V2 | G3 | MOYEN | 🟠 Moyenne |
| SO6 (reset TPM, rejeu PCR) | BS3, BS7 | V2 | G3 | MOYEN | 🟠 Moyenne |
| SO7 (retour sur ancien slot) | BS12 | V2 | G3 | MOYEN | 🟠 Moyenne |
| SO8 (coupure pendant le commit) | BS1, BS6 | V3 | G3 | ÉLEVÉ | 🔴 Haute |
| SO9 (header hostile pré-auth) | BS1, BS2 | V2 | G2 | MOYEN | 🟠 Moyenne |
| SO10 (épuisement du TPM) | BS3 | V3 | G2 | MOYEN | 🟠 Moyenne |
| SO11 (canal de contrôle local) | BS10 | V2 | G3 | MOYEN | 🟠 Moyenne |
| SO12 (logs saturés ou falsifiés) | BS11 | V3 | G2 | MOYEN | 🟠 Moyenne |
| SO13 (dépendance malveillante) | BS9 | V2 | G4 | ÉLEVÉ | 🔴 Haute |
| SO14 (vol de la clé de signature) | BS9 | V2 | G4 | ÉLEVÉ | 🔴 Haute |
| SO15 (chunks réordonnés ou mélangés) | BS1, BS2 | V1 | G4 | FAIBLE | 🟢 Basse |
| SO16 (TPM comme oracle) | BS3, BS4 | V4 | G3 | ÉLEVÉ | 🟠 Moyenne (arbitrage) |
| SO17 (malfaision de provisionnement) | BS3, BS1 | V4 | G4 | ÉLEVÉ | 🔴 Haute |
| SO18 (forensique mémoire post-crash) | BS4 | V3 | G3 | ÉLEVÉ | 🔴 Haute |
| SO19 (compromission flotte-wide) | BS3, BS4, BS9 | V3 | G4 | ÉLEVÉ | 🔴 Haute |
| SO20 (re-provisionnement device capturé) | BS3, BS4, BS1 | V3 | G3 | ÉLEVÉ | 🔴 Haute |

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
| R9 : Compromission de la clé de signature éditeur (SS6, SO14) | G4 | V2 | **ÉLEVÉ** | ❌ Inacceptable |
| R10 : Compromission de la chaîne d'approvisionnement logicielle (SS7, SO13) | G4 | V2 | **ÉLEVÉ** | ❌ Inacceptable |
| R11 : Freeze et maintien sur version vulnérable (SS8, SO7) | G3 | V3 | **ÉLEVÉ** | ❌ Inacceptable |
| R12 : Déni de service et brick (SS9, SO8 à SO11) | G3 | V3 | **ÉLEVÉ** | ❌ Inacceptable |
| R13 : Exfiltration ou falsification via le payload (SS10, SO12) | G3 | V2 | **MOYEN** | ⚠️ Tolérable (sous conditions) |
| R14 : Reset du TPM et rejeu de PCR (SS11, SO6) | G3 | V2 | **MOYEN** | ⚠️ Tolérable (sous conditions) |
| R15 : Injection de fautes sur le SoC (SS12) | G4 | V1 | **FAIBLE** | ✅ Acceptable (hypothèses matérielles) |
| R16 : Divulgation par le propriétaire du device, TPM comme oracle (SS13, SO16) | G3 | V4 | **ÉLEVÉ** | ⚠️ À arbitrer (acceptation ou réduction) |
| R17 : Erreur de provisionnement — KEK incorrecte (SS14, SO17) | G4 | V4 | **CRITIQUE** | ❌ Inacceptable |
| R18 : Compromission flotte-wide par KEK unique (SS15, SO19) | G4 | V3 | **ÉLEVÉ** | ❌ Inacceptable |
| R19 : Re-provisionnement d'un device capturé (SS16, SO20) | G3 | V3 | **ÉLEVÉ** | ❌ Inacceptable |

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

#### R9 : Compromission de la clé de signature éditeur (ÉLEVÉ → MOYEN)

**Stratégie** : **Réduction** (révocation, séparation des clés) + **Transfert** (organisation des clés côté éditeur, hors périmètre)

**Mesures** :
1. ✅ **Création des bundles hors ligne** (REQ-BUN-1)
2. ✅ **Clé asymétrique de signature et KEK symétrique distinctes** : sans la KEK, produire un bundle exige de réutiliser une clé de session déjà connue de l'attaquant ; cette séparation n'a de valeur que si le TPM n'est pas un oracle (R16)
3. 🔲 **Stockage de la clé de signature en HSM** et cérémonie de clés ; KEK stockée séparément
4. 🔲 **Mécanisme de révocation et de rotation** de la clé de vérification (NV index, autorité de secours)
5. 🔲 **Double signature ou quorum** pour les releases (signatures hybrides prévues dans `05`)
6. 🔲 **Journal d'audit des signatures**

**Risque résiduel après traitement** : **MOYEN** (la compromission reste possible, sa durée est bornée par la révocation)

---

#### R10 : Compromission de la chaîne d'approvisionnement logicielle (ÉLEVÉ → MOYEN)

**Stratégie** : **Réduction**

**Mesures** :
1. ✅ **Versions épinglées, `Cargo.lock` versionné** (REQ-CRY-2) ; primitives issues des bibliothèques des projets de l'ANSSI (REQ-CRY-1)
2. 🔲 **`cargo audit`, `cargo vet`, `cargo deny` en CI**
3. 🔲 **Vendoring** et revue des mises à jour des crates critiques (`aes-gcm-siv`, `hkdf`, `tss-esapi`)
4. 🔲 **Build reproductible, SBOM, signature des artefacts** (niveaux SLSA)
5. 🔲 **Chaîne de boot vérifiant `updated`** (voir R3)

**Risque résiduel après traitement** : **MOYEN**

---

#### R11 : Freeze et maintien sur version vulnérable (ÉLEVÉ → MOYEN)

**Stratégie** : **Réduction**

**Mesures** :
1. ✅ **Anti-rollback** (compteur NV) et `min_firmware_version` : traitent le downgrade
2. 🔲 **Mécanisme de fraîcheur** : métadonnées signées avec horodatage ou expiration, vérifiées par le device (approche de TUF)
3. 🔲 **Alerte côté device et côté serveur** quand une version installée est trop ancienne ou qu'aucune vérification n'a abouti depuis N jours
4. 🔲 **Environnement U-Boot signé ou mesuré**, et vérification du slot booté contre le compteur (SO7)
5. 🔲 **Un bundle = un jeu cohérent d'images** (question ouverte 3 de `02`)

**Risque résiduel après traitement** : **MOYEN** (un attaquant réseau peut toujours bloquer, mais le blocage devient visible)

---

#### R12 : Déni de service et brick (ÉLEVÉ → FAIBLE)

**Stratégie** : **Réduction**

**Mesures** :
1. ✅ **Limites de ressources du jail** (cgroups) et **mémoire bornée** (REQ-BUN-5)
2. ✅ **Rate limiting et backoff** sur les tentatives (A11)
3. 🔲 **A/B intégré à la machine à états** et protocole de commit atomique défini de bout en bout (SO8)
4. 🔲 **Health-check et watchdog** au premier boot, rollback automatique
5. 🔲 **Bornes numériques** sur `chunk_size`, `chunk_count`, taille du manifeste ; fuzzing du header (SO9)
6. 🔲 **Spécification du canal de contrôle** `updatectl` ↔ `updated` (SO11)
7. 🔲 **Gestion RAII des sessions TPM** et test de saturation (SO10)

**Risque résiduel après traitement** : **FAIBLE**

---

#### R13 : Exfiltration ou falsification via le payload (MOYEN → FAIBLE)

**Stratégie** : **Réduction**

**Mesures** :
1. ✅ **Réseau toujours isolé** (`CLONE_NEWNET`), policy machine, bind mounts en lecture seule
2. 🔲 **Quota et format de la sortie contrôlée** ; fin des écritures du payload hors des zones autorisées
3. 🔲 **Journal d'événements critiques séparé** de la sortie du payload, avec extension de PCR
4. 🔲 **Vérification post-écriture du slot** contre les hash des artefacts du manifeste

**Risque résiduel après traitement** : **FAIBLE**

---

#### R14 : Reset du TPM et rejeu de PCR (MOYEN → FAIBLE)

**Stratégie** : **Réduction**

**Mesures** :
1. ✅ **`PolicyAuthorize`** : permet de faire évoluer la policy sans re-provisionner la KEK, mais sa signature n'est pas un secret et ne protège pas d'un rejeu
2. 🔲 **`PolicyPCR` obligatoire** (et non optionnelle) dans la policy de la KEK
3. 🔲 **Ligne de reset du TPM reliée au reset du SoC** (conception matérielle)
4. 🔲 **Lier la policy au header** (question 13 de `03`)

**Risque résiduel après traitement** : **FAIBLE**

---

#### R15 : Injection de fautes sur le SoC (FAIBLE)

**Stratégie** : **Acceptation** (hypothèses matérielles, 1.6)

**Mesures** :
1. 🔲 **Faire porter la décision par le TPM** : tant que la vérification du header est séquencée par le logiciel (question 13 de `03`), un saut de test dans `updated` permet de présenter un header non authentique
2. 🔲 **Choix d'un SoC et d'un TPM** avec contre-mesures documentées
3. 🔲 **Tests de glitching** avant certification (nice-to-have)

**Risque résiduel après traitement** : **FAIBLE**

---

#### R16 : Divulgation par le propriétaire du device, TPM comme oracle (ÉLEVÉ, arbitrage)

**Stratégie** : **À décider** entre deux options.

- **Option A, acceptation** : la confidentialité n'est garantie que contre les attaquants A1 à A4, pas contre celui qui contrôle un device. Ce choix est à consigner dans `01-threat-model.md` (hors périmètre). Risque résiduel : **ÉLEVÉ**, assumé.
- **Option B, réduction** :
  1. 🔲 **Lier la policy de la KEK au header ou au bundle** (question 13 de `03`) pour supprimer l'oracle
  2. 🔲 **KEK par device ou par famille** (question 6 de `00`) pour limiter l'effet d'un device ouvert
  3. 🔲 **Restriction d'accès à `/dev/tpmrm0`** en défense en profondeur (root la contourne)
  4. ✅ **Clé de session unique par bundle** et clés par chunk (déjà spécifiés) : l'extraction depuis la RAM n'expose qu'un bundle

  Risque résiduel : **MOYEN** (un device ouvre encore les bundles qu'il installe)

**Note** : ce risque croise R18 (compromission flotte-wide) et R19 (re-provisionnement). Une KEK par device (R18) réduit la surface d'exposition d'un device unique. Une politique de rotation de KEK (R19) réduit la fenêtre d'exposition rétroactive.

---

#### R17 : Erreur de provisionnement — KEK incorrecte (CRITIQUE)

**Stratégie** : **Réduction** (prévention par conception + détection)

**Mesures** :
1. ✅ **Vérification post-provisionnement** (déjà prévue) : `TPM2_ReadLock` + vérification que `KEK_id` match `header.kek_id`
2. 🔲 **Bundle de migration** : un bundle signé « de migration » charge un nouveau `kek_id` dans le TPM sans casser les bundles existants
3. 🔲 **Pool de KEK** : un device contient plusieurs KEK ; un bundle spécifie le `kek_id` cible parmi celles présentes
4. 🔲 **Processus de vérification de provisioning** : lot de test avec bundle signé, vérification qu'aucun device ne rejette
5. 🔲 **Détection en campo** : un device qui rejette N bundles consécutifs demande au serveur quelle KEK il attend
6. 🔲 **Cérémonie de clés** : procédure formelle pour ajouter une KEK à un device déjà en campo
7. 🔲 **Interdiction du re-provisionnement sans bundle de migration** : politique organisationnelle

**Risque résiduel après traitement** : **MOYEN** (erreur humaine résiduelle si politique de migration violée)

---

#### R18 : Compromission flotte-wide par KEK unique (ÉLEVÉ)

**Stratégie** : **Réduction** (limitation de l'impact par segmentation)

**Mesures** :
1. ✅ **Clé de session unique par bundle** (déjà spécifiée) : l'extraction d'une session key n'expose qu'un bundle
2. 🔲 **KEK par device** (unique à chaque device, provisionnée en usine) : compromettre un device ne compromet que ce device
3. 🔲 **Ou : KEK par famille** (une KEK par modèle de device, pas par flotte) : compromettre un lot n'ouvre qu'un modèle
4. 🔲 **Mécanisme de migration de KEK** : un bundle « de migration » permet de charger une nouvelle KEK sans casser les bundles existants
5. 🔲 **Rotation de KEK** : cérémonie de clés pour passer d'une ancienne KEK à une nouvelle sans interrompre les devices en campo
6. 🔲 **Liste de validité temporelle** : une KEK périmée ne peut plus déchiffrer de nouveaux bundles

**Risque résiduel après traitement** : **MOYEN** (un device ne compromet plus que ce device, mais un lot de même modèle peut rester exposé)

---

#### R19 : Re-provisionnement d'un device capturé (ÉLEVÉ)

**Stratégie** : **Réduction** (limitation de la fenêtre d'exposition rétroactive)

**Mesures** :
1. ✅ **`kek_id` dans le header** (déjà spécifié) : le device rejette les bundles dont le `kek_id` ne correspond pas
2. ✅ **Clé de session unique par bundle** (déjà spécifiée) : l'extraction d'une session key n'expose qu'un bundle
3. 🔲 **Politique de validité temporelle des KEK** : une KEK périmée ne peut plus déchiffrer de nouveaux bundles (mais peut-elle déchiffrer d'anciens ?)
4. 🔲 **Bundle de migration** : un bundle « de migration » signe le nouveau `kek_id` et le charge dans le TPM ; les anciens bundles restent valables mais ne peuvent plus être installés après migration
5. 🔲 **Politique de rotation** : une politique de rotation de KEK (tous les N bundles ou M années) réduit la fenêtre d'exposition d'une KEK compromise
6. 🔲 **Revocation list** : une liste de KEK révoquées stockée dans le TPM ; un bundle dont le `kek_id` est dans la liste est rejeté
7. 🔲 **Interdiction du re-provisionnement sans cérémonie de clés** : politique organisationnelle

**Risque résiduel après traitement** : **MOYEN** (un device re-provisionné ne peut plus utiliser d'anciens bundles capturés, mais la compromission d'un device non re-provisionné reste possible)

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
| Lier la policy de la KEK au header (question 13 de `03`) et trancher KEK par device ou par flotte | Architecte | T+2 semaines | 🔲 À faire |
| Spécifier la révocation et la rotation de la clé de vérification et de la KEK | Architecte | T+2 semaines | 🔲 À faire |
| Spécifier la fraîcheur des mises à jour (horodatage ou expiration signés) | Architecte | T+2 semaines | 🔲 À faire |
| Intégrer l'A/B et le protocole de commit atomique à `04-update-flow.md` | Architecte | T+2 semaines | 🔲 À faire |
| Rendre `PolicyPCR` obligatoire et relier le reset du TPM au reset du SoC | Architecte, matériel | T+2 semaines | 🔲 À faire |
| Spécifier le bundle de migration (police de KEK, procédure de re-provisionnement) | Architecte | T+4 semaines | 🔲 À faire |
| Spécifier la politique de rotation de KEK et revocation list | Architecte | T+4 semaines | 🔲 À faire |

#### Priorité 2 : Haute (pendant implémentation)

| Action | Responsable | Échéance | Statut |
|---|---|---|---|
| Implémenter seccomp sur le supervisor | Dev | T+4 semaines | 🔲 À faire |
| Implémenter hidepid=2 sur /proc | Dev | T+4 semaines | 🔲 À faire |
| Implémenter cgroups v2 pour le jail | Dev | T+4 semaines | 🔲 À faire |
| Fuzzing du parser manifeste | QA | T+6 semaines | 🔲 À faire |
| Fuzzing du parser chunks | QA | T+6 semaines | 🔲 À faire |
| Fuzzing du parser de header (bornes numériques) | QA | T+6 semaines | 🔲 À faire |
| Activer `cargo audit`, `cargo vet`, `cargo deny` en CI ; vendoring | Dev | T+4 semaines | 🔲 À faire |
| Spécifier le protocole `updatectl` ↔ `updated` (`SO_PEERCRED`, commandes, pas de chemin client) | Dev | T+4 semaines | 🔲 À faire |
| Définir quotas et format de la sortie du payload, journal critique séparé | Dev | T+4 semaines | 🔲 À faire |
| Signer ou mesurer l'environnement U-Boot et vérifier le slot booté | Dev | T+6 semaines | 🔲 À faire |
| Spécifier le bundle de migration (procédure de re-provisionnement) | Architecte | T+4 semaines | 🔲 À faire |
| Spécifier la politique de rotation de KEK et revocation list | Architecte | T+4 semaines | 🔲 À faire |

#### Priorité 3 : Moyenne (après MVP)

| Action | Responsable | Échéance | Statut |
|---|---|---|---|
| Implémenter TPM2_Quote (attestation distante) | Dev | T+12 semaines | 🔲 À faire |
| Implémenter la rotation des clés (KEK, signature) | Dev | T+12 semaines | 🔲 À faire |
| Spécifier le bundle de migration (procédure de re-provisionnement) | Architecte | T+12 semaines | 🔲 À faire |
| Spécifier la politique de rotation de KEK et revocation list | Architecte | T+12 semaines | 🔲 À faire |
| Audit formel du code critique (Prusti, Kani) | Dev | T+24 semaines | 🔲 À faire |
| Certification Common Criteria ou ANSSI CSPN | Dev lead | T+52 semaines | 🔲 À faire |
| Build reproductible, SBOM, signature des artefacts | Dev lead | T+12 semaines | 🔲 À faire |
| Clé de signature en HSM, cérémonie de clés, double signature | Éditeur | T+12 semaines | 🔲 À faire |
| Tests de glitching et de saturation du TPM sur matériel réel | QA | T+24 semaines | 🔲 À faire |

### 5.4 Cadre de suivi des risques

#### Indicateurs de risque

| Indicateur | Fréquence | Seuil d'alerte | Action |
|---|---|---|---|
| Nombre de CVE kernel affectant le device | Hebdomadaire | CVE critique | Mise à jour kernel urgente |
| Nombre de tentatives de mise à jour échouées | Quotidienne | > 5 échecs consécutifs | Investigation (attaque par exhaustion TPM ?) |
| Temps de vérification du header | Quotidienne | Variance > 2σ | Investigation (timing attack ?) |
| Nombre de devices avec TPM réinitialisé | Mensuelle | > 1% de la flotte | Investigation (attaque physique coordonnée ?) |
| Nombre de vulnérabilités découvertes dans le code | Mensuelle | CVE critique | Patch urgent |
| Âge de la version installée sur chaque device | Hebdomadaire | > N jours sans mise à jour ni contact serveur | Investigation (freeze, SS8) |
| Volume et fréquence de la sortie du payload | Par exécution | Quota dépassé | Interruption du jail, investigation (SO12) |
| Mises à jour interrompues (coupure, échec de health-check) | Quotidienne | > 1% de la flotte | Revue du protocole de commit (SO8) |
| Écarts de PCR au boot ou resets du TPM détectés | Quotidienne | Tout événement | Investigation (SO6) |
| Alertes `cargo audit` et changements de dépendances | À chaque build | Advisory critique ou dépendance non revue | Blocage de la release (SS7) |

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

[[6]] The Update Framework (TUF), "Specification" (attaques par rollback, freeze et mix-and-match). Disponible sur : https://theupdateframework.github.io/specification/latest/

[[7]] OpenSSF, "SLSA — Supply-chain Levels for Software Artifacts". Disponible sur : https://slsa.dev/

---

**Prochaine itération** : Après implémentation des mesures de Priorité 1 et 2, réévaluation des risques résiduels et mise à jour de l'analyse EBIOS RM.
