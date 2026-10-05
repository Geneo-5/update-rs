# 00 — Vue d'ensemble

Statut : Brouillon

## Objet

Système de mise à jour d'une plateforme embarquée de type SolidRun Clearfog, écrit en Rust.

## Exigences globales

- **REQ-GEN-1** — L'authenticité du payload DOIT être garantie, ancrée dans un TPM 2.0.
- **REQ-GEN-2** — La confidentialité du payload DOIT être garantie, ancrée dans un TPM 2.0.
- **REQ-GEN-3** — L'archive de mise à jour est créée offline et DOIT être lisible en streaming
  lors de la récupération sur le device (voir [02-bundle-format.md](02-bundle-format.md)).
- **REQ-GEN-4** — Le projet DOIT se cross-compiler pour la cible principale, la SolidRun
  Clearfog Pro (ARMv7, `armv7-unknown-linux-gnueabihf`), équipée d'un TPM 2.0 en révision 1.38
  de la spécification TCG.
- **REQ-GEN-5** — Les algorithmes cryptographiques DOIVENT s'appuyer sur les mêmes
  bibliothèques que les projets GitHub de l'ANSSI (voir [05-crypto.md](05-crypto.md)).
- **REQ-GEN-6** — Le payload DOIT s'exécuter dans un **environnement jail isolé** (tmpfs,
  namespaces, seccomp, capabilities réduites), construit dynamiquement à partir d'un
  manifeste authentifié (voir [06-jail.md](06-jail.md)).

## Cibles

| Cible | Triple Rust | Rôle |
|---|---|---|
| ARMv7 (Clearfog Pro, Armada 388) | `armv7-unknown-linux-gnueabihf` | principale |
| Hôte | selon poste de dev | développement, CI, `bundle-tool` |

## Glossaire

| Terme | Définition |
|---|---|
| Bundle | Archive de mise à jour (header + manifeste + images chiffrées), créée offline |
| Slot | Partition (ou jeu de partitions) bootable ; A/B = deux slots alternés |
| PCR | Platform Configuration Register du TPM |
| NV index | Emplacement de stockage non volatil du TPM |
| **KEK** | **Key Encryption Key** : clé symétrique AES-256 résidant dans le TPM, utilisée pour déballer la clé de session du bundle |
| **Clé de session** | Clé AES-256-GCM-SIV éphémère (Key 32 octets + IV 12 octets) encapsulée dans le header, déchiffrée via la KEK |
| **AES Keywrap** | AES Key Wrap with Padding (RFC 5649), mécanisme d'encapsulation symétrique avec intégrité intégrée (RFC 3394 pour la variante sans padding) |
| **EK / AK** | Endorsement Key / Attestation Key : clés racines ECC du TPM utilisées pour les sessions chiffrées |
| **PolicyAuthorize** | Mécanisme TPM 2.0 liant l'usage d'une clé à la signature d'une autorité (ici, la clé ECC de vérification du header) |
| **Jail** | Environnement sandboxé d'exécution du payload, construit dynamiquement à partir d'un tmpfs et de bind mounts |
| **JailManifest** | Description déclarative du jail (namespaces, fsset, entrypoint, capabilities, seccomp), contenue dans le manifeste du bundle |
| **fsset** | Liste ordonnée de règles de montage dans le jail (dirs, bind mounts host, payload files, dev nodes, etc.) |
| **Seccomp** | Filtre BPF limitant les syscalls disponibles dans le jail (profils `strict`, `default`, `custom`) |

## Questions ouvertes

1. Quel bootloader et quelle chaîne de boot (U-Boot, mesures dans le TPM, secure boot SoC) ?
2. Quel TPM (modèle exact, révision 1.38 de la spécification), quel bus (SPI/I2C) et quelle distribution embarquée (Buildroot, Yocto, autre) ?
3. Mise à jour de quoi : rootfs seul, noyau, bootloader, firmware du TPM ?
4. Taille typique des bundles et débit/connectivité réseau visés ?
5. Les bundles sont-ils par appareil (une KEK par device), par famille (une KEK par famille), ou pour toute la flotte ?
6. Quelle version minimale du noyau Linux sur la cible (`openat2` ≥ 5.6, `MS_NOSYMFOLLOW` ≥ 5.10, `cgroup.kill` ≥ 5.14) ?
