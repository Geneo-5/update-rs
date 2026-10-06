# Gestion du cycle de vie des clés cryptographiques

## 1. Objet

Ce document définit la politique de gestion des clés cryptographiques nécessaires à l'intégration de `update-rs`.

Il couvre le cycle de vie complet des clés :

```text
Demande
  ↓
Génération
  ↓
Enrôlement / affectation
  ↓
Introduction / injection
  ↓
Stockage
  ↓
Utilisation
  ↓
Rotation / renouvellement
  ↓
Suspension / révocation
  ↓
Fin d'utilisation
  ↓
Destruction
```

Cette politique est conçue pour être compatible avec les principes du **NIST SP 800-57 Part 1 Rev. 5**, du **NIST SP 800-57 Part 2 Rev. 1** et de l'**ANSSI RGS v2.0 – Annexe B2 « Gestion des clés cryptographiques »**.

> **Important — portée et statut**
>
> Ce document constitue une recommandation d'intégration pour `update-rs`. Il ne constitue ni une certification ANSSI, ni une conformité automatique au RGS, ni une certification FIPS/NIST d'un composant.
>
> Le RGS B2 publié par l'ANSSI date de 2012. Il reste ici une référence française explicite pour les principes de gestion des clés ; les choix cryptographiques et les paramètres doivent également être vérifiés contre les recommandations ANSSI actuellement applicables et l'état de l'art au moment du déploiement.
>
> Le NIST SP 800-57 définit la gestion des clés comme couvrant notamment la génération, le stockage, l'établissement, l'entrée/sortie, l'utilisation et la destruction des clés et informations associées. citeturn0search11turn0search7

---

## 2. Référentiels

### 2.1 ANSSI

La référence principale est :

**ANSSI — Référentiel Général de Sécurité v2.0, Annexe B2 — Gestion des clés cryptographiques, version 2.00 du 8 juin 2012.**

Cette annexe traite notamment :

- de la demande de clé ;
- de la génération ;
- de l'affectation ;
- de l'introduction dans le système ;
- de l'utilisation ;
- de la fin de vie ;
- de l'effacement ;
- de l'environnement de confiance ;
- de la différenciation des clés selon leur usage.

L'ANSSI précise notamment qu'une clé doit avoir un cycle de vie défini et que la fin de vie de l'ensemble des clés utilisées doit être prévue. L'annexe B2 distingue également la génération, l'affectation et l'introduction d'une clé dans l'environnement applicatif. citeturn2search11turn2search1

### 2.2 NIST

Les références utilisées sont :

- **NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management: Part 1 – General** ;
- **NIST SP 800-57 Part 2 Rev. 1 — Recommendation for Key Management: Part 2 – Best Practices for Key Management Organizations**.

Le Part 1 couvre les bonnes pratiques de gestion des clés, les types de clés, leurs exigences de protection et les fonctions de gestion. citeturn0search7turn0search10

Le Part 2 traite de la politique de gestion des clés, de la documentation, des responsabilités, de la protection des clés et de leur gestion sur l'ensemble du cycle de vie. NIST recommande notamment de formaliser une politique couvrant génération, établissement, comptabilisation, stockage, transport, utilisation et destruction. citeturn0search39turn0search0

---

# 3. Principes de sécurité

## 3.1 Une clé = un usage

Chaque clé doit avoir un usage cryptographique explicitement défini.

Une même clé ne doit pas être réutilisée pour plusieurs fonctions de sécurité distinctes, par exemple :

- signature et chiffrement ;
- signature de bundles et Secure Boot ;
- chiffrement de données et authentification ;
- production et développement.

Cette séparation suit notamment la **RègleUsage-1** du RGS B2, qui impose un usage unique des clés, sauf mécanisme de dérivation ou primitive conçue spécifiquement pour plusieurs services. citeturn2search1

---

## 3.2 Les clés privées et secrets doivent rester dans un environnement de confiance

Une clé privée ou une clé symétrique secrète ne doit jamais être exposée inutilement.

Pour les clés à fort impact :

- privilégier un HSM ou un composant matériel sécurisé ;
- limiter les opérations autorisées ;
- contrôler les opérateurs ;
- journaliser les opérations ;
- empêcher l'export de la clé lorsque celui-ci n'est pas nécessaire.

L'ANSSI rappelle que les éléments privés ou secrets doivent être utilisés dans un environnement de confiance responsable de leur stockage et de leur gestion. citeturn2search1

---

## 3.3 Les clés ne doivent pas être confondues avec les données publiques associées

Pour une clé asymétrique :

```text
clé privée  → secret critique
clé publique → donnée publique
```

La clé publique peut être distribuée dans le système sans compromettre la confidentialité de la clé privée.

En revanche, son **association avec l'identité et le rôle attendu doit être authentifiée**.

---

## 3.4 Toute clé doit avoir un propriétaire et une politique

Chaque clé doit être associée à :

- un identifiant ;
- un propriétaire ;
- un rôle ;
- un algorithme ;
- des paramètres cryptographiques ;
- un usage ;
- une date de création ;
- une date d'activation ;
- une crypto-période ;
- une politique de renouvellement ;
- une politique de révocation ;
- une politique de destruction ;
- un niveau de criticité ;
- un emplacement de stockage ;
- une procédure de récupération si applicable.

Cette approche est cohérente avec le principe NIST de formaliser une politique de gestion des clés et les informations associées à leur protection. citeturn0search39

---

# 4. Inventaire des clés de `update-rs`

L'architecture doit distinguer au minimum les familles suivantes.

| Identifiant | Clé | Type | Utilisation | Emplacement de référence |
|---|---|---|---|---|
| `K-SIGN-REL` | clé privée de signature release | asymétrique | signature des bundles | HSM / environnement de signature |
| `K-VERIFY-REL` | clé publique release | asymétrique | vérification des bundles | device / configuration de confiance |
| `K-KEK-DEVICE` | KEK | symétrique | protection des secrets locaux | **TPM, non exportable** |
| `K-TPM-AK` | Attestation Key | asymétrique | attestation TPM, si utilisée | TPM |
| `K-TPM-EK` | Endorsement Key | asymétrique | identité du TPM | TPM |
| `K-BOOT-*` | clés Secure Boot | asymétrique | chaîne de boot | firmware / HSM |
| `K-RECOVERY-*` | clés de récupération | selon architecture | recovery / RMA | environnement de confiance |
| `K-DEV-*` | clés de développement | asymétrique | développement/tests | environnement dev |

Les clés Secure Boot ne sont **pas gérées par `update-rs`** mais doivent être intégrées dans la même politique de cycle de vie lorsqu'elles participent à la chaîne de confiance du produit.

---

# 5. Cycle de vie de `K-SIGN-REL`

## 5.1 Rôle

`K-SIGN-REL` est la clé privée utilisée pour signer les bundles de production.

Elle constitue une **racine de confiance de l'éditeur**.

La compromission de cette clé permet potentiellement de produire des bundles que les équipements considéreront comme authentiques.

Elle doit donc être considérée comme une clé de criticité maximale.

---

## 5.2 Demande

Une demande de génération doit être explicitement autorisée.

Elle doit identifier :

- le produit ;
- l'environnement (`production`, `qualification`, `development`) ;
- l'usage ;
- l'algorithme ;
- le niveau de sécurité ;
- la crypto-période ;
- les personnes autorisées ;
- la procédure d'approbation.

Aucune clé de production ne doit être créée simplement parce qu'un développeur en a besoin.

---

## 5.3 Génération

La génération doit être réalisée :

- dans un environnement de confiance ;
- avec un générateur d'aléa approprié ;
- de préférence directement dans un HSM lorsque celui-ci est utilisé ;
- sans sauvegarder la clé privée en clair sur un poste de travail.

L'ANSSI impose notamment que la génération locale aléatoire utilise un générateur d'aléa conforme au référentiel et recommande un environnement de confiance pour la génération centralisée. citeturn2search1

### Recommandation

Pour une clé de signature de production :

```text
                    ┌───────────────┐
                    │ Opérateurs    │
                    │ autorisés     │
                    └───────┬───────┘
                            │ approbation
                            ▼
                    ┌───────────────┐
                    │ HSM           │
                    │ RNG sécurisé  │
                    └───────┬───────┘
                            │
                    clé privée créée
                            │
                            ▼
                    non exportable
```

La clé privée ne doit pas apparaître dans :

- Git ;
- CI logs ;
- fichiers temporaires ;
- artefacts de build ;
- tickets ;
- messagerie ;
- sauvegardes ordinaires.

---

## 5.4 Stockage

Le stockage recommandé est un HSM ou une solution offrant une protection équivalente.

La clé privée doit :

- être non exportable si possible ;
- nécessiter une authentification forte ;
- être accessible uniquement aux rôles autorisés ;
- faire l'objet d'un audit ;
- être séparée des systèmes de développement.

La sauvegarde de la clé doit elle-même être protégée selon une politique équivalente.

---

## 5.5 Utilisation

La signature doit idéalement suivre :

```text
source
  ↓
build
  ↓
tests
  ↓
artefact
  ↓
validation release
  ↓
HSM
  ↓
signature
```

et non :

```text
build machine
  ↓
clé privée locale
  ↓
signature automatique
```

Le système de signature doit vérifier que l'artefact présenté à la signature correspond exactement à l'artefact validé.

---

## 5.6 Rotation

La rotation peut être déclenchée par :

- fin de crypto-période ;
- évolution cryptographique ;
- changement organisationnel ;
- changement de produit ;
- suspicion de compromission ;
- compromission confirmée.

Une rotation ne doit pas simplement remplacer la clé côté serveur.

Il faut également prévoir :

1. introduction de la nouvelle clé publique sur les équipements ;
2. période de coexistence éventuelle ;
3. signature avec la nouvelle clé ;
4. retrait de l'ancienne clé ;
5. traitement des équipements hors ligne ;
6. procédure de retour arrière ;
7. destruction de l'ancienne clé lorsque son usage n'est plus nécessaire.

---

## 5.7 Révocation / compromission

En cas de compromission présumée :

```text
Détection
   ↓
Suspension immédiate
   ↓
Blocage de la signature
   ↓
Analyse
   ↓
Révocation
   ↓
Nouvelle clé
   ↓
Distribution du nouveau trust anchor
   ↓
Reprise contrôlée
```

La révocation doit être traitée comme un événement de sécurité critique.

Le système doit notamment déterminer comment empêcher un attaquant de continuer à utiliser l'ancienne clé.

---

## 5.8 Destruction

Après fin d'utilisation :

- supprimer les copies inutiles ;
- détruire la clé dans le HSM lorsque possible ;
- détruire les sauvegardes devenues inutiles ;
- vérifier qu'aucune copie opérationnelle ne subsiste ;
- conserver uniquement les informations publiques et les éléments nécessaires à l'audit ou à la vérification historique.

La fin de vie et l'effacement doivent être explicitement prévus dans l'architecture de gestion des clés. citeturn2search1

---

# 6. Cycle de vie de `K-VERIFY-REL`

`K-VERIFY-REL` est la partie publique de la chaîne de confiance utilisée par le device pour vérifier les bundles.

## 6.1 Génération

Elle est créée avec `K-SIGN-REL`.

La clé publique doit être associée à :

- un identifiant de clé ;
- un produit ;
- une version de politique ;
- un rôle de signature ;
- une période de validité.

---

## 6.2 Introduction dans le produit

La clé publique doit être introduite lors d'une procédure de provisioning de confiance.

Elle peut par exemple être :

- intégrée dans l'image de référence ;
- intégrée dans une partition de confiance ;
- provisionnée au premier enrôlement ;
- protégée par Secure Boot.

L'intégrateur doit empêcher qu'un attaquant puisse remplacer cette clé publique par sa propre clé.

---

## 6.3 Rotation

La rotation de la clé publique est un point critique.

Le device doit connaître la nouvelle clé **avant** qu'elle ne soit utilisée comme unique clé de signature.

Un schéma de transition peut être :

```text
K1
 │
 ├── accepte K1
 │
 └── introduit K2
          │
          ├── accepte K1
          └── accepte K2
                    │
                    ▼
              retrait de K1
```

Le mécanisme exact dépend de la capacité de `update-rs` à gérer plusieurs trust anchors.

---

## 6.4 Révocation

Une clé publique compromise doit pouvoir être retirée de la politique de confiance.

Il faut donc prévoir un mécanisme de mise à jour du trust store indépendant de la clé compromise, ou une racine supérieure permettant cette opération.

---

# 7. Cycle de vie de `K-KEK-DEVICE`

## 7.1 Rôle

La KEK protège les secrets cryptographiques locaux utilisés par `update-rs`.

La propriété fondamentale du projet est :

> **La KEK ne doit jamais quitter le TPM en clair.**

La KEK est donc une clé **liée au matériel et au TPM du device**.

---

## 7.2 Génération

La génération doit être réalisée dans l'environnement de confiance approprié.

Deux architectures sont possibles :

### Génération dans le TPM

```text
TPM RNG / TPM key generation
          ↓
       KEK TPM
          ↓
      non exportable
```

C'est l'architecture à privilégier lorsque le mécanisme TPM utilisé par `update-rs` le permet.

### Génération externe puis import sécurisé

Si une génération externe est nécessaire, la clé doit être transférée vers le TPM par une procédure d'importation protégée.

La clé ne doit jamais être transportée en clair sur un canal non contrôlé.

---

## 7.3 Provisioning

Le provisioning doit être effectué lors de la fabrication ou de l'enrôlement sécurisé du device.

La procédure doit :

1. identifier le device ;
2. identifier le TPM ;
3. vérifier l'état attendu du TPM ;
4. créer/importer la KEK ;
5. appliquer les politiques TPM ;
6. configurer les NV indexes nécessaires ;
7. associer la clé au produit ;
8. vérifier son fonctionnement ;
9. enregistrer les métadonnées d'inventaire.

---

## 7.4 Stockage

La KEK doit rester dans le TPM.

Le système ne doit pas stocker une copie brute de la KEK dans :

- `/etc` ;
- la flash ;
- un fichier de configuration ;
- une variable d'environnement ;
- un secret CI ;
- un dump mémoire persistant.

Des **blobs TPM protégés** peuvent être persistés si l'architecture TPM le nécessite ; ces blobs ne doivent pas être assimilés à une exportation de la KEK en clair.

---

## 7.5 Utilisation

L'utilisation doit être réalisée via les primitives TPM prévues par l'architecture.

Le daemon ne doit pas charger la KEK en clair dans son espace utilisateur si la primitive TPM permet d'éviter cette exposition.

---

## 7.6 Sauvegarde

Une KEK liée à un TPM ne doit pas être sauvegardée comme une clé symétrique ordinaire.

La politique doit distinguer :

```text
backup de données
        ≠
backup de KEK
```

La stratégie de récupération doit définir explicitement ce qui se passe lorsque :

- le TPM est remplacé ;
- la carte mère est remplacée ;
- le TPM est effacé ;
- le device est retourné en RMA ;
- la flash est restaurée.

---

## 7.7 Rotation

La KEK peut être renouvelée lors :

- d'un remplacement matériel ;
- d'une migration cryptographique ;
- d'une compromission ;
- d'une réinitialisation contrôlée ;
- d'une évolution de l'architecture.

Une rotation doit préserver l'accès aux données encore nécessaires.

---

## 7.8 Destruction

La destruction doit utiliser les mécanismes TPM appropriés :

- destruction de l'objet ;
- suppression de la clé persistante ;
- réinitialisation contrôlée du TPM si nécessaire.

Une procédure `TPM_Clear` ne doit jamais être utilisée comme opération normale de maintenance sans analyser ses conséquences sur l'identité, l'attestation, le Secure Boot et les données protégées.

---

# 8. Cycle de vie de `K-TPM-EK`

L'Endorsement Key (EK) est une clé d'identité du TPM fournie ou provisionnée selon le constructeur.

`update-rs` ne doit pas créer arbitrairement une nouvelle EK si l'architecture TPM repose sur l'EK constructeur.

## Gestion

La procédure doit :

1. détecter le TPM ;
2. identifier l'EK ;
3. vérifier le certificat EK lorsqu'il est disponible ;
4. enregistrer l'identité du TPM ;
5. associer le TPM au device ;
6. détecter un remplacement inattendu.

L'EK doit rester protégée par le TPM.

Elle ne doit pas être exportée comme clé privée.

---

# 9. Cycle de vie de `K-TPM-AK`

L'Attestation Key est utilisée lorsqu'une architecture d'attestation distante est mise en œuvre.

Elle permet notamment d'établir une preuve cryptographique liée au TPM.

## Génération

L'AK doit idéalement être générée dans le TPM :

```text
TPM
 └── création AK
       ├── clé privée → TPM
       └── clé publique → système d'attestation
```

La clé privée AK ne doit pas être exportée.

## Enrôlement

Le service d'attestation doit associer :

```text
Device ID
    +
TPM identity
    +
AK public key
```

L'association initiale doit être réalisée dans un environnement de confiance.

## Rotation

Une nouvelle AK peut être créée lors :

- d'un changement de politique ;
- d'une suspicion de compromission ;
- d'une réinitialisation TPM ;
- d'une procédure RMA.

---

# 10. Clés Secure Boot

Les clés Secure Boot sont **hors scope fonctionnel de `update-rs`**, mais elles doivent être incluses dans la gouvernance cryptographique globale du produit si Secure Boot est utilisé comme racine de confiance.

Selon la plateforme, on peut rencontrer notamment :

```text
Platform Key (PK)
       ↓
Key Exchange Key (KEK)
       ↓
Signature Database (db)
       ↓
Bootloader / kernel / EFI binaries
```

Les rôles exacts dépendent de l'architecture Secure Boot retenue.

## Règle fondamentale

Les clés Secure Boot ne doivent pas être réutilisées comme clés de signature des bundles `update-rs`.

Cela respecte le principe de séparation des usages.

---

# 11. Clés de développement

Les clés de développement doivent être distinctes des clés de production.

```text
Production
    K-SIGN-REL-PROD

Qualification
    K-SIGN-REL-QA

Development
    K-SIGN-REL-DEV
```

Une clé de développement ne doit jamais être acceptée par un équipement de production.

Inversement, la clé de production ne doit pas être installée dans les environnements de développement.

---

# 12. Procédure de provisioning usine

Le provisioning initial doit être considéré comme une **opération de sécurité**, et non comme une simple installation logicielle.

## 12.1 Préparation

Avant production :

- générer les clés de production ;
- vérifier les HSM ;
- préparer les trust anchors ;
- préparer les politiques TPM ;
- préparer les certificats/identifiants nécessaires ;
- valider les procédures de récupération.

## 12.2 Provisioning du device

Pour chaque device :

```text
1. Identifier le device
       ↓
2. Identifier le TPM
       ↓
3. Vérifier le TPM
       ↓
4. Vérifier Secure Boot
       ↓
5. Générer / créer KEK
       ↓
6. Configurer TPM policies
       ↓
7. Installer trust anchor update-rs
       ↓
8. Configurer anti-rollback
       ↓
9. Vérifier les PCR attendues
       ↓
10. Effectuer un test de mise à jour
       ↓
11. Enregistrer le résultat
```

---

# 13. Premier enrôlement

Le premier enrôlement est particulièrement critique car le device ne possède pas encore nécessairement les moyens cryptographiques permettant de vérifier les informations qu'on lui fournit.

L'ANSSI considère explicitement le premier enrôlement comme une opération nécessitant des mesures physiques et organisationnelles de confiance lorsque les moyens cryptographiques ne sont pas encore établis. citeturn2search1

Il faut donc éviter :

```text
Device neuf
    ↓
réseau non authentifié
    ↓
"voici ta clé de confiance"
```

et privilégier :

```text
Device identifié
    ↓
canal / environnement de provisioning de confiance
    ↓
installation du trust anchor
    ↓
vérification
    ↓
activation
```

---

# 14. Inventaire et traçabilité

Chaque clé de production doit être enregistrée dans un inventaire.

L'inventaire doit au minimum contenir :

| Champ | Exemple |
|---|---|
| Key ID | `update-release-prod-2026-01` |
| Rôle | bundle signing |
| Algorithme | Ed25519 |
| Produit | update-rs device |
| Environnement | production |
| Date génération | ISO 8601 |
| Activation | ISO 8601 |
| Expiration / fin crypto-période | ISO 8601 |
| Propriétaire | rôle organisationnel |
| HSM / emplacement | identifiant logique |
| État | active |
| Clé précédente | Key ID |
| Clé suivante | Key ID |
| Procédure révocation | référence |
| Procédure destruction | référence |

Les journaux doivent permettre de répondre à :

> Qui a demandé, approuvé, créé, utilisé, suspendu, révoqué ou détruit cette clé ?

NIST SP 800-57 Part 2 insiste sur la nécessité de documenter la politique, les responsabilités et les pratiques de gestion des clés. citeturn0search0turn0search39

---

# 15. États d'une clé

Le cycle de vie peut être modélisé avec les états suivants :

```text
                  ┌───────────────┐
                  │   REQUESTED   │
                  └───────┬───────┘
                          ↓
                  ┌───────────────┐
                  │ PRE-ACTIVATION│
                  └───────┬───────┘
                          ↓
                  ┌───────────────┐
                  │    ACTIVE     │
                  └───┬───────┬───┘
                      │       │
             suspend  │       │ expire/retire
                      ↓       ↓
                ┌────────┐ ┌────────────┐
                │SUSPENDED│ │ DEACTIVATED│
                └────┬───┘ └──────┬─────┘
                     │             │
                     └──────┬──────┘
                            ↓
                    ┌────────────┐
                    │ COMPROMISED│
                    └─────┬──────┘
                          ↓
                    ┌───────────┐
                    │ DESTROYED │
                    └───────────┘
```

NIST SP 800-57 décrit explicitement des états tels que *Pre-Activation*, *Active*, *Suspended*, *Deactivated*, *Compromised* et *Destroyed*, ainsi que les transitions associées. citeturn2search13

---

# 16. Crypto-période

Chaque clé doit avoir une crypto-période définie.

Elle dépend notamment :

- du type de clé ;
- de son usage ;
- de son niveau de criticité ;
- de la quantité de données/opérations protégées ;
- de l'évolution cryptanalytique ;
- de la politique produit.

La durée ne doit pas être choisie uniquement pour des raisons opérationnelles.

L'ANSSI rappelle le principe d'une durée de vie maximale associée à une clé, et NIST demande que les politiques définissent les durées de vie maximales des clés et métadonnées. citeturn1search20turn0search39

---

# 17. Révocation d'urgence

Une procédure d'urgence doit exister avant qu'un incident ne survienne.

## Compromission d'une clé de signature

```text
Détection
   ↓
Gel des releases
   ↓
Désactivation clé HSM
   ↓
Analyse des bundles signés
   ↓
Révocation trust anchor
   ↓
Nouvelle clé
   ↓
Distribution nouvelle confiance
   ↓
Reprise
```

## Compromission d'une KEK device

Le traitement est différent car la clé est liée au device.

Il faut notamment déterminer :

- si la KEK est récupérable ;
- si les données doivent être déchiffrées avant rotation ;
- si le TPM doit être réinitialisé ;
- comment ré-enrôler le device ;
- comment éviter la réutilisation de la clé compromise.

---

# 18. Sauvegarde et récupération

La sauvegarde des clés doit être traitée différemment selon leur nature.

| Clé | Backup |
|---|---|
| clé privée release | **oui**, contrôlé et chiffré / HSM backup |
| clé publique release | oui, sans exigence de confidentialité |
| KEK TPM | **pas de copie brute** |
| EK privée | non exportée |
| AK privée | non exportée |
| Secure Boot private keys | backup contrôlé selon architecture |
| clés de développement | politique spécifique |

NIST distingue le stockage opérationnel, le stockage de sauvegarde et l'archivage lorsque la disponibilité à long terme des informations de clé est nécessaire. citeturn0search40

Une sauvegarde de clé privée de production doit donc être :

- chiffrée ;
- soumise à un contrôle d'accès ;
- testée périodiquement ;
- protégée contre la destruction simultanée avec le stockage primaire ;
- documentée.

---

# 19. Séparation des rôles

Pour les clés critiques, il est recommandé de séparer au minimum :

```text
Key Custodian
     │
     ├── conserve / administre
     │
Release Manager
     │
     ├── autorise la release
     │
Security Officer
     │
     └── supervise la politique
```

Une même personne ne devrait pas pouvoir, seule :

1. créer une clé de production ;
2. l'utiliser pour signer ;
3. modifier la politique ;
4. supprimer les traces d'audit.

Cette séparation réduit le risque de compromission interne.

---

# 20. Interdictions

Les pratiques suivantes sont interdites pour les clés de production :

- stocker une clé privée dans Git ;
- stocker une clé privée dans une image Docker ;
- stocker une clé privée dans les logs CI ;
- transmettre une clé privée par e-mail ;
- partager une clé privée entre développeurs ;
- utiliser une clé de développement en production ;
- réutiliser une clé Secure Boot pour `update-rs` ;
- copier une KEK TPM en clair ;
- mettre une clé secrète dans un fichier de configuration ;
- utiliser une même clé pour plusieurs usages sans justification cryptographique explicite ;
- conserver indéfiniment une clé retirée sans politique d'archivage.

---

# 21. Contrôles avant mise en production

Avant la première mise en production, les points suivants doivent être vérifiés.

### Gouvernance

- [ ] propriétaire de chaque clé défini ;
- [ ] procédure d'approbation définie ;
- [ ] séparation des rôles définie ;
- [ ] inventaire créé ;
- [ ] crypto-périodes définies ;
- [ ] procédure de révocation définie ;
- [ ] procédure de destruction définie.

### Génération

- [ ] générateur d'aléa approprié ;
- [ ] génération réalisée dans un environnement de confiance ;
- [ ] clé privée jamais exposée inutilement ;
- [ ] génération auditée.

### Stockage

- [ ] HSM ou mécanisme équivalent pour les clés critiques ;
- [ ] accès restreint ;
- [ ] authentification forte ;
- [ ] audit activé ;
- [ ] sauvegarde protégée.

### Device / TPM

- [ ] TPM identifié ;
- [ ] EK vérifiée lorsque applicable ;
- [ ] KEK créée/importée selon procédure ;
- [ ] KEK non exportable ;
- [ ] policies TPM vérifiées ;
- [ ] trust anchor installé ;
- [ ] anti-rollback configuré.

### Rotation

- [ ] mécanisme de rotation testé ;
- [ ] coexistence ancienne/nouvelle clé testée ;
- [ ] révocation testée ;
- [ ] équipements hors ligne pris en compte.

### Destruction

- [ ] destruction de clé testée ;
- [ ] destruction des copies temporaires vérifiée ;
- [ ] procédure RMA définie.

---

# 22. Matrice de responsabilités

| Activité | `update-rs` | Éditeur | Intégrateur | Fabricant TPM / plateforme |
|---|:---:|:---:|:---:|:---:|
| Définition politique de clés | | ✓ | ✓ | |
| Génération clé release | | **✓** | | |
| Protection clé release | | **✓** | | |
| Signature bundle | outil / protocole | **✓** | | |
| Trust anchor device | support | ✓ | **✓** | |
| Génération KEK | support | | **✓** | TPM |
| Stockage KEK | ✓ mécanisme | | ✓ provisioning | **✓** |
| Provisioning TPM | | | **✓** | ✓ |
| EK | | | ✓ vérification | **✓** |
| AK | support éventuel | | ✓ | ✓ |
| Secure Boot keys | | | **✓** | ✓ selon plateforme |
| Rotation | | **✓** | **✓** | |
| Révocation | support | **✓** | **✓** | |
| Destruction | support | **✓** | **✓** | |
| Audit | événements applicatifs | **✓** | **✓** | ✓ |

---

# 23. Relation avec `update-rs`

Cette politique ne doit pas être interprétée comme signifiant que `update-rs` implémente toutes les fonctions décrites.

`update-rs` fournit principalement des mécanismes permettant d'utiliser les clés dans le contexte de la mise à jour.

L'intégrateur reste responsable de l'environnement dans lequel ces clés sont générées, provisionnées, stockées et administrées.

En particulier :

```text
                     ┌─────────────────────────────┐
                     │ Key Management Organization  │
                     │                             │
                     │ génération                  │
                     │ HSM                         │
                     │ approbation                 │
                     │ rotation                    │
                     │ révocation                  │
                     └──────────────┬──────────────┘
                                    │
                              trust anchor
                                    │
                                    ▼
                     ┌─────────────────────────────┐
                     │        Device               │
                     │                             │
                     │ Secure Boot                 │
                     │ TPM                         │
                     │  └── KEK                    │
                     │                             │
                     │ update-rs                   │
                     │  └── vérification bundle   │
                     └─────────────────────────────┘
```

---

# 24. Exigences minimales recommandées

Pour un produit de production, les exigences minimales suivantes sont recommandées :

| ID | Exigence |
|---|---|
| `KEY-001` | Chaque clé possède un usage unique documenté. |
| `KEY-002` | Chaque clé possède un propriétaire et une crypto-période. |
| `KEY-003` | Les clés de production sont générées dans un environnement de confiance. |
| `KEY-004` | Les clés privées de signature de production sont protégées par HSM ou mécanisme équivalent. |
| `KEY-005` | Une clé de développement ne peut pas être acceptée par un équipement de production. |
| `KEY-006` | La KEK device ne quitte jamais le TPM en clair. |
| `KEY-007` | Le provisioning initial est réalisé par une procédure de confiance. |
| `KEY-008` | Toute clé dispose d'une procédure de rotation. |
| `KEY-009` | Toute clé dispose d'une procédure de révocation. |
| `KEY-010` | Toute clé dispose d'une procédure de destruction. |
| `KEY-011` | Les opérations critiques de gestion des clés sont journalisées. |
| `KEY-012` | Les sauvegardes des clés critiques sont protégées et testées. |
| `KEY-013` | Les clés Secure Boot et les clés `update-rs` sont distinctes. |
| `KEY-014` | Une compromission de `K-SIGN-REL` entraîne une procédure d'urgence documentée. |
| `KEY-015` | Une procédure RMA existe pour les clés liées au TPM. |

---

# 25. Références normatives

### ANSSI

- **ANSSI, Référentiel Général de Sécurité v2.0, Annexe B2 — Gestion des clés cryptographiques, version 2.00, 8 juin 2012.**  
  urlDocument officiel ANSSI — RGS v2.0 B2https://cyber.gouv.fr/sites/default/files/2022-10/RGS_v-2-0_B2.pdf

- **ANSSI, Référentiel Général de Sécurité v2.0 — documents et annexes.**  
  urlPage officielle RGS ANSSIhttps://cyber.gouv.fr/reglementation/reglementation-identite-confiance-numerique/securite-echanges-voie-electronique/referentiel-general-de-securite/documents-referentiel-general-de-securite/

- **ANSSI, Guide des mécanismes cryptographiques — règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques.**  
  urlGuide officiel ANSSI sur les mécanismes cryptographiqueshttps://cyber.gouv.fr/sites/default/files/2021/03/anssi-guide-mecanismes_crypto-2.04.pdf

### NIST

- **NIST SP 800-57 Part 1 Rev. 5 — Recommendation for Key Management: Part 1 – General, 2020.**  
  urlNIST SP 800-57 Part 1 Rev. 5https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final

- **NIST SP 800-57 Part 2 Rev. 1 — Recommendation for Key Management: Part 2 – Best Practices for Key Management Organizations, 2019.**  
  urlNIST SP 800-57 Part 2 Rev. 1https://csrc.nist.gov/pubs/sp/800/57/pt2/r1/final

- **NIST Key Management Guidelines.**  
  urlNIST Key Management Guidelineshttps://csrc.nist.gov/Projects/Key-Management/Key-Management-Guidelines

---

## 26. Note sur la conformité

La présente politique reprend des principes issus de l'ANSSI et du NIST, mais **« compatible avec » ne signifie pas « conforme à »**.

Une revendication de conformité, de qualification ou de certification nécessite une analyse du périmètre complet, incluant notamment :

- le matériel ;
- le TPM ;
- le HSM ;
- les logiciels ;
- les procédures ;
- les opérateurs ;
- les locaux ;
- la chaîne de fabrication ;
- la chaîne de développement ;
- les mécanismes de récupération ;
- les contrôles d'accès ;
- les preuves et audits.

Le document doit donc être utilisé comme **base de politique de gestion des clés pour l'intégration de `update-rs`**, et non comme substitut à une évaluation de sécurité.
