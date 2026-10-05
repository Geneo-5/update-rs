# 01 — Modèle de menace

Statut : Brouillon (proposition à valider)

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
- **REQ-THR-4** — La KEK NE DOIT JAMAIS être exportable du TPM, ni même en clair dans la RAM, sauf pendant une brève fenêtre sous policy de vérification de signature (fallback x3).
- **REQ-THR-5** — Un attaquant écoutant le bus TPM (A4) NE DOIT PAS obtenir la clé de session, la KEK, ou les paramètres de commande sensibles.
- **REQ-THR-6** — La fenêtre d'exposition de la KEK en RAM (cas fallback) DOIT être minimisée (zeroize immédiat, mlock, pas de core dump).

## Menaces spécifiques au jail

Le payload s'exécute dans un environnement jail (voir [06-jail.md](06-jail.md)). Les
menaces suivantes s'ajoutent aux menaces globales ci-dessus :

| Id | Attaquant | Capacités |
|---|---|---|
| J1 | Payload malveillant | Exécute du code dans le jail, tente d'échapper au sandbox (bind mounts mal configurés, device nodes sensibles) |
| J2 | Payload avec binaires privilégiés | Tente d'exécuter des binaires setuid ou de conserver des capabilities après execve |
| J3 | Payload avec accès proc/sys | Tente d'utiliser `/proc`/`/sys` en écriture pour escalader (atténué par options `ro,nosuid,nodev,noexec`) |
| J4 | Payload consommant des ressources | Fork bomb, épuisement mémoire/CPU (atténué par cgroups, PID namespace, timeouts) |

## Questions ouvertes

1. Les bundles sont-ils par appareil, par famille d'appareils, ou pour toute la flotte ?
2. Faut-il la résistance à un attaquant post-quantique « store now, decrypt later » sur la confidentialité ?
3. Quel niveau de protection du bus TPM (sessions chiffrées obligatoires — décidé, voir `03-tpm.md`) ?
4. Modèle de menace pour le fallback x3 : la répétition probabiliste suffit-elle contre A6 ?
5. Que se passe-t-il si l'EK/AK du TPM est compromise (root of trust hardware) ?
6. Un attaquant A6 peut-il forcer le mode fallback même si le TPM supporte AES Keywrap, pour exposer la KEK ?
