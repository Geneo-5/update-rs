# 01 — Modèle de menace

Statut : Brouillon (proposition à valider)

> **Note** : Une analyse de sécurité approfondie est disponible dans [07-security-analysis.md](07-security-analysis.md).
> Elle identifie des scénarios d'attaque additionnels, des points à clarifier, et les recommandations du guide Rust ANSSI applicables.

## Actifs

- Intégrité et authenticité du logiciel installé sur le device.
- Confidentialité du contenu des bundles (propriété intellectuelle, secrets embarqués).
- **KEK (Key Encryption Key)** : clé symétrique AES-256 résidant dans le TPM, utilisée pour déballer les clés de session des bundles.
- **Clé de session** : clé AES-GCM éphémère (Key + IV) déballée à chaque mise à jour, utilisée pour déchiffrer les chunks.
- **Clé publique de vérification ECC** : ancre de confiance, utilisée par le TPM pour valider les signatures des headers.
- **Sessions chiffrées TPM** : canal sécurisé entre le logiciel et le TPM, protégeant les commandes sensibles.
- **Index NV** : ancre de confiance (hash), compteur anti-rollback, paramètres du dispositif.
- Disponibilité du device (pas de brick après une mise à jour ratée ou malveillante).

## Attaquants considérés

| Id | Attaquant | Capacités |
|---|---|---|
| A1 | Réseau | Observe, modifie, rejoue, coupe le transport |
| A2 | Détenteur d'un bundle | Possède le fichier, tente de le lire ou de le modifier |
| A3 | Accès physique au stockage | Extrait ou modifie la flash hors tension |
| A4 | Accès physique au bus TPM | Écoute ou rejoue des commandes SPI/I2C (atténué par sessions chiffrées) |
| A5 | Rollback | Fait installer une version ancienne, validement signée, mais vulnérable |
| A6 | Compromission logicielle partielle | Contrôle le processus utilisateur pendant la mise à jour, tente d'exploiter la fenêtre TOCTOU entre vérification de signature et déchiffrement |
| A7 | Réutilisation de header | Tente de rejouer un header valide avec un payload différent (atténué par binding hash manifeste) |
| A8 | Bundle cross-device | Tente d'installer un bundle signé pour un autre dispositif (atténué par `kek_id` + policy PCR) |

## Hors périmètre (à valider)

- Compromission root **après** le boot : le TPM ne l'empêche pas d'invoquer la logique de
  mise à jour.
- Attaques par canaux auxiliaires sur le SoC.
- Compromission de la clé de signature côté éditeur (traité par l'organisation des clés,
  pas par ce projet).

## Exigences

- **REQ-THR-1** — Un bundle modifié, tronqué, réordonné ou rejoué DOIT être rejeté.
- **REQ-THR-2** — Un bundle ne DOIT pas être déchiffrable sans le TPM (et l'état de boot) du device visé.
- **REQ-THR-3** — Une version inférieure au compteur anti-rollback DOIT être rejetée.
- **REQ-THR-4** — La KEK NE DOIT JAMAIS quitter le TPM, ni même transiter en clair dans la RAM. Le TPM DOIT effectuer le déchiffrement AES Keywrap (RFC 5649) en interne et retourner uniquement la clé de session déballée. Sans AES Keywrap, le TPM est utiliser 3 fois avec un déchiffrement AES et 3 fenêtre de validation TPM avec échange chiffré.
- **REQ-THR-5** — Un attaquant écoutant le bus TPM (A4) NE DOIT PAS obtenir la clé de session, la KEK, ou les paramètres de commande sensibles.
- **REQ-THR-6** — La chaîne de confiance DOIT être ancrée depuis le ROM/SoC secure boot jusqu'au TPM (bootloader vérifié → kernel vérifié → rootfs vérifié → `updated` vérifié → TPM policy/PCR).
- **REQ-THR-7** — Tout contenu issu du bundle DOIT être traité comme **hostile** jusqu'à sa transformation en une représentation interne validée et bornée.
- **REQ-THR-8** — Aucune donnée contrôlée par le bundle ne DOIT déterminer directement une primitive privilégiée sans passer par une policy indépendante du bundle.

## Menaces spécifiques au jail

Le payload s'exécute dans un environnement jail (voir [06-jail.md](06-jail.md)). Les
menaces suivantes s'ajoutent aux menaces globales ci-dessus :

| Id | Attaquant | Capacités |
|---|---|---|
| J1 | Payload malveillant | Exécute du code dans le jail, tente d'échapper au sandbox (bind mounts mal configurés, device nodes sensibles) |
| J2 | Payload avec binaires privilégiés | Tente d'exécuter des binaires setuid ou de conserver des capabilities après execve |
| J3 | Payload avec accès proc/sys | Tente d'utiliser `/proc`/`/sys` en écriture pour escalader (atténué par options `ro,nosuid,nodev,noexec`) |
| J4 | Payload consommant des ressources | Fork bomb, épuisement mémoire/CPU (atténué par cgroups, PID namespace, timeouts) |

## Phase Critique de Mise à Jour (Critical Update Phase — CUP)

**Définition** : toute opération qui transforme des données provenant du bundle en état persistant du système est une **phase critique** et doit être traitée comme une opération de sécurité privilégiée.

Cela inclut :
- Parsing du bundle, manifeste, configuration
- Validation et migration de format
- Génération de configuration
- Écriture sur MTD/block devices
- Remplacement atomique de fichiers
- Modification de permissions/ownership
- Création de symlinks
- Modification de fichiers utilisés par des services privilégiés

**Propriété de sécurité** : même si le bundle est signé par un éditeur de confiance, son contenu doit être considéré comme **adversarial au niveau de l'implémentation**. La signature garantit l'authenticité, pas l'absence de bugs d'exploitation dans le parser.

**Architecture supervisor/worker** :
```
                  PRIVILEGED (supervisor)
                      │
             ┌────────▼────────┐
             │ Update supervisor│
             │                  │
             │ policy / state   │
             │ TPM              │
             │ MTD              │
             │ filesystem      │
             └────────┬────────┘
                      │
              minimal IPC (validated IR)
                      │
             ┌────────▼────────┐
             │ Update worker   │  (sandboxed)
             │                 │
             │ parse           │
             │ validate        │
             │ transform       │
             └─────────────────┘
```

Le **worker** peut être très fortement sandboxé. Le **supervisor** conserve les privilèges indispensables (MTD, filesystem, TPM, mount, activation).

## Questions ouvertes

1. Les bundles sont-ils par appareil, par famille d'appareils, ou pour toute la flotte ?
2. Faut-il la résistance à un attaquant post-quantique « store now, decrypt later » sur la confidentialité ?
3. Quel niveau de protection du bus TPM (sessions chiffrées obligatoires — décidé, voir `03-tpm.md`) ?
4. Que se passe-t-il si l'EK/AK du TPM est compromise (root of trust hardware) ?
5. Quel bootloader (U-Boot) et quel mécanisme de secure boot pour ancrer la chaîne de confiance jusqu'au TPM ?
