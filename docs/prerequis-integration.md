# Prérequis d'intégration et éléments hors scope

**Statut : Recommandations d'intégration**

## 1. Objet

`update-rs` fournit le mécanisme de mise à jour sécurisé de la plateforme embarquée : format et vérification des bundles, confidentialité du payload, utilisation du TPM 2.0, anti-rollback, et exécution du payload dans un environnement isolé.

Ces mécanismes ne constituent toutefois pas, à eux seuls, une chaîne de confiance complète de la plateforme.

Ce document décrit les **éléments qui sont hors du périmètre de `update-rs` mais qui doivent être fournis, configurés ou garantis par l'intégrateur, le fabricant de la plateforme ou l'éditeur** lorsque les objectifs de sécurité associés sont recherchés.

> **Principe important :** l'absence d'une fonction dans `update-rs` n'est pas nécessairement une faiblesse du projet. Certaines garanties appartiennent à une couche différente du système : SoC/ROM, bootloader, noyau Linux, système de fichiers, matériel, provisioning, infrastructure de clés, CI/CD ou exploitation.

Les niveaux utilisés dans ce document sont :

- **Requis** : indispensable pour que l'objectif de sécurité concerné puisse être considéré comme satisfait.
- **Fortement recommandé** : nécessaire pour une défense en profondeur crédible ou pour réduire fortement un chemin d'attaque identifié.
- **Recommandé** : mesure de durcissement utile mais dépendante du contexte.

---

## 2. Vue synthétique

| Domaine | Hors scope `update-rs` | Niveau |
|---|---|---|
| Secure Boot / chaîne de démarrage | ROM/SoC, bootloader, vérification du kernel et du rootfs | **Requis** si la chaîne de confiance complète est revendiquée |
| Intégrité du système déjà démarré | Protection du kernel, rootfs, services et configuration hors mécanisme de mise à jour | **Requis** |
| Compromission `root` post-boot | Empêcher qu'un root compromis contourne le daemon | **Fortement recommandé** |
| Contrôle d'accès aux MTD/flash | Permissions, LSM, politique d'accès matériel, bootloader | **Requis** |
| Protection physique | Boîtier, debug ports, JTAG/SWD, accès SPI/I²C/flash | **Requis** selon le niveau de menace |
| Provisioning TPM | Injection initiale des clés, verrouillage et configuration du TPM | **Requis** |
| Matériel TPM | Choix, authentification et intégrité du composant TPM | **Requis** |
| Clés éditeur | HSM, stockage, rotation, révocation, séparation des rôles | **Requis** |
| Sécurité de la chaîne de build | Reproductibilité, CI, signature, protection des runners | **Fortement recommandé** |
| Configuration Linux | systemd/init, permissions, capabilities, seccomp, LSM, mounts | **Requis** |
| Disponibilité / récupération | A/B, bootloader, watchdog, recovery, power-loss | **Requis** pour les objectifs de disponibilité |
| Transport | TLS/authentification serveur, contrôle de distribution, anti-DoS | **Recommandé** |
| Monitoring / audit | Conservation et protection des logs | **Fortement recommandé** |
| Validation des données persistées | Politique indépendante du bundle pendant la CUP | **Requis** |

---

## 3. Secure Boot et chaîne de confiance

### 3.1 Ce que fait `update-rs`

`update-rs` peut utiliser l'état de la plateforme, le TPM et les PCR dans sa politique cryptographique. Le modèle de menace définit explicitement une chaîne :

```text
ROM / SoC Secure Boot
        ↓
Bootloader vérifié
        ↓
Kernel vérifié
        ↓
Rootfs vérifié
        ↓
updated vérifié
        ↓
Policy TPM / PCR
```

Cette chaîne est référencée par `REQ-THR-6`.

### 3.2 Ce que `update-rs` ne fait pas

`update-rs` **n'implémente pas le Secure Boot du SoC** et ne peut pas, à lui seul, garantir que le code exécuté avant `updated` est authentique.

En particulier, le projet ne remplace pas :

- la racine de confiance ROM du SoC ;
- la vérification cryptographique du bootloader ;
- la vérification du kernel ;
- la vérification du DTB/firmware nécessaire ;
- la vérification du rootfs ;
- le verrouillage de la configuration du bootloader ;
- la politique de boot et de rollback du bootloader.

### 3.3 Prérequis

Pour revendiquer `REQ-THR-6`, la plateforme doit fournir une chaîne de Secure Boot adaptée au matériel cible.

**Niveau : Requis pour `REQ-THR-6`.**

Sans cette chaîne, les garanties de `update-rs` commencent à partir d'un système dont l'intégrité initiale est supposée.

> Exemple : un attaquant capable de remplacer le kernel ou le rootfs par une version malveillante avant le démarrage de `updated` peut potentiellement exécuter un `updated` modifié ou contourner les protections attendues, même si les bundles eux-mêmes sont correctement signés.

### 3.4 Mesures complémentaires

Il est recommandé de :

- verrouiller les variables de boot ;
- empêcher un boot alternatif depuis USB/SD lorsque le produit final ne le nécessite pas ;
- désactiver ou verrouiller les interfaces de récupération non nécessaires ;
- faire correspondre les mesures PCR au modèle réel de démarrage ;
- documenter précisément les PCR utilisées et leur signification ;
- empêcher le remplacement du bootloader sans procédure de confiance équivalente.

---

## 4. Intégrité du système après le boot

`update-rs` protège le processus de mise à jour ; il ne transforme pas automatiquement l'ensemble du système Linux en système immuable ou mesuré.

L'intégrateur doit donc définir comment sont protégés :

- kernel et modules ;
- rootfs ;
- fichiers de configuration système ;
- unités systemd/services ;
- scripts de démarrage ;
- binaires exécutés par `updated` ;
- bibliothèques dynamiques ;
- règles udev ;
- fichiers de politique et de provisioning TPM.

**Niveau : Requis** lorsque l'objectif est de garantir que seul un environnement de confiance peut exécuter `updated`.

Une solution peut par exemple combiner Secure Boot, rootfs vérifié/immuable, dm-verity ou mécanisme équivalent, permissions strictes et LSM.

---

## 5. Compromission `root` après le boot

La compromission de `root` après le démarrage est explicitement hors périmètre du modèle de menace actuel.

Un processus disposant d'un contrôle root suffisant peut potentiellement :

- interagir directement avec le TPM ;
- appeler ou remplacer le daemon ;
- modifier les fichiers de configuration ;
- modifier les périphériques MTD si les droits le permettent ;
- modifier les politiques locales ;
- exploiter les interfaces du kernel ;
- interférer avec la phase critique de mise à jour.

Le TPM ne doit donc pas être considéré comme une protection absolue contre un système Linux déjà compromis.

### Recommandation

L'environnement d'intégration doit limiter au maximum les possibilités d'obtention de `root` :

- services exposés minimaux ;
- comptes sans privilèges ;
- séparation des services ;
- capabilities minimales ;
- SELinux/AppArmor ou mécanisme équivalent ;
- seccomp lorsque pertinent ;
- désactivation des interfaces de debug en production ;
- permissions strictes sur `/dev`, `/sys`, `/proc` et les MTD.

**Niveau : Fortement recommandé.**

---

## 6. Accès aux MTD, flash et stockage brut

`update-rs` peut orchestrer une mise à jour, mais la sécurité de l'accès au stockage sous-jacent dépend du système d'exploitation et du matériel.

L'intégrateur doit contrôler qui peut accéder à :

```text
/dev/mtd*
/dev/mtdblock*
/dev/mmc*
/dev/sd*
/dev/nvme*
```

ainsi qu'aux interfaces permettant de modifier directement la flash.

### Point important

Un attaquant ayant les privilèges nécessaires pour modifier arbitrairement :

- les MTD ;
- le bootloader ;
- les partitions système ;
- les fichiers de configuration critiques ;

peut potentiellement contourner une partie des garanties applicatives.

**Niveau : Requis.**

Le daemon `updated` doit disposer uniquement des privilèges nécessaires à son fonctionnement. Les autres processus ne doivent pas pouvoir accéder directement aux zones critiques.

---

## 7. Protection physique et interfaces de debug

La protection cryptographique ne remplace pas la sécurité physique.

L'intégrateur doit traiter :

- JTAG/SWD ;
- UART de debug ;
- console bootloader ;
- SPI/I²C du TPM ;
- accès direct à la flash ;
- ports USB permettant un boot alternatif ;
- boutons ou straps de recovery ;
- accès à la carte mère.

Le modèle de menace considère explicitement l'accès physique au stockage et au bus TPM.

**Niveau : Requis** selon le niveau d'attaquant considéré.

Mesures recommandées :

- désactivation du debug en production ;
- verrouillage JTAG/SWD ;
- authentification de la console de récupération ;
- protection contre le remplacement du TPM ;
- protection contre le remplacement ou la lecture de la flash ;
- contrôle des modes boot/recovery.

---

## 8. Provisioning et configuration du TPM

`update-rs` définit l'utilisation de la KEK, des politiques TPM, des PCR et de l'anti-rollback, mais **le provisioning initial du matériel est une responsabilité d'intégration**.

Il doit notamment définir :

- génération ou injection de la KEK ;
- création de la policy ;
- installation de la clé publique de vérification ;
- configuration des NV indexes ;
- initialisation du compteur anti-rollback ;
- sélection des PCR ;
- association du matériel à son identité ;
- procédure de remplacement/RMA ;
- comportement après un `TPM_Clear`.

La KEK doit rester non exportable ; la spécification du projet impose qu'elle ne quitte jamais le TPM.

**Niveau : Requis.**

Le provisioning doit être réalisé dans un environnement de confiance et être documenté comme une étape de fabrication/supply-chain, pas comme une opération normale de mise à jour.

---

## 9. Authenticité du TPM et du matériel

La présence d'un TPM 2.0 ne garantit pas automatiquement que le TPM connecté est celui attendu.

Le système d'intégration doit définir, selon le niveau de menace :

- identité du TPM ;
- EK et certificat EK ;
- procédure de provisioning ;
- détection d'un remplacement ;
- politique en cas de TPM réinitialisé ;
- protection du bus TPM.

Pour les environnements à forte exigence, une attestation du TPM et une vérification de son identité peuvent être nécessaires.

**Niveau : Requis ou fortement recommandé selon le modèle de menace.**

---

## 10. Gestion des clés côté éditeur

La clé privée servant à signer les bundles constitue une **racine de confiance organisationnelle**.

`update-rs` vérifie des signatures ; il ne protège pas le système d'information de l'éditeur qui possède la clé privée.

La gestion des clés doit donc couvrir :

- stockage dans HSM ou mécanisme équivalent ;
- contrôle d'accès ;
- séparation des rôles ;
- authentification forte ;
- journalisation ;
- rotation ;
- révocation ;
- procédure d'urgence en cas de compromission ;
- protection des clés de développement contre les clés de production ;
- distinction entre clés de test et clés de production.

**Niveau : Requis.**

Une compromission de la clé de signature peut rendre un bundle malveillant cryptographiquement valide.

---

## 11. Chaîne de build et supply chain

La sécurité d'un bundle signé dépend également de la sécurité du logiciel qui le produit.

L'environnement de build doit notamment protéger :

- dépôt source ;
- dépendances ;
- toolchain Rust ;
- CI/CD ;
- runners ;
- secrets de signature ;
- `bundle-tool` ;
- artefacts intermédiaires.

Mesures recommandées :

- builds reproductibles lorsque possible ;
- verrouillage des dépendances ;
- revue des mises à jour de dépendances ;
- SAST/lint/tests dans la CI ;
- signature des artefacts ;
- séparation build / signature ;
- runner de signature isolé ;
- approbation humaine pour une release de production.

**Niveau : Fortement recommandé.**

---

## 12. Sécurité du service `updated`

Le service de mise à jour est normalement exécuté avec des privilèges élevés.

L'intégrateur doit donc fournir une configuration d'exécution cohérente avec le modèle de sécurité.

Elle doit notamment traiter :

- utilisateur/groupe du daemon ;
- capabilities ;
- accès aux MTD ;
- accès TPM ;
- accès aux sockets ;
- accès aux fichiers de configuration ;
- répertoires temporaires ;
- limites CPU/mémoire/processus ;
- systemd sandboxing ou équivalent ;
- permissions des fichiers ;
- protection contre l'exécution simultanée.

`update-rs` prévoit déjà un verrouillage d'instance et une isolation du payload, mais la configuration globale du service reste dépendante de la plateforme.

**Niveau : Requis.**

---

## 13. Phase critique de mise à jour (CUP)

La **Phase Critique de Mise à Jour** doit être considérée comme une frontière de sécurité.

Toute opération qui transforme une donnée provenant du bundle en état persistant du système doit être traitée comme une opération privilégiée.

Cela inclut notamment :

```text
réception
   ↓
parsing
   ↓
validation
   ↓
transformation
   ↓
mise à jour
   ↓
réécriture
   ↓
état persistant
```

Le fait que le contenu provienne d'un bundle signé ne signifie pas que toutes les données résultantes peuvent être utilisées directement comme paramètres privilégiés.

### Prérequis d'intégration

Pendant la CUP :

1. les données doivent être considérées comme hostiles jusqu'à validation ;
2. les valeurs doivent être bornées ;
3. la politique de sécurité ne doit pas être entièrement déterminée par le bundle ;
4. les chemins de fichiers doivent être validés ;
5. les opérations privilégiées doivent être explicitement autorisées ;
6. les écritures doivent être atomiques lorsque possible ;
7. un échec doit laisser le système dans un état connu.

**Niveau : Requis.**

C'est particulièrement important pour les fichiers de configuration : `update-rs` peut garantir l'authenticité du bundle, mais **la politique de ce qu'il est autorisé à modifier dans la configuration système appartient à l'intégrateur**.

---

## 14. Configuration système et fichiers de configuration

Les fichiers de configuration constituent une frontière importante entre le contenu signé par l'éditeur et le comportement du système.

L'intégrateur doit définir :

- quels fichiers peuvent être modifiés ;
- quelles clés/valeurs sont modifiables ;
- les valeurs maximales/minimales ;
- les formats acceptés ;
- les valeurs interdites ;
- les permissions finales ;
- le propriétaire des fichiers ;
- les services pouvant être activés/désactivés ;
- les paramètres nécessitant un reboot ;
- les paramètres nécessitant une validation supplémentaire.

### Principe recommandé

Ne pas considérer :

```text
"bundle signé" == "configuration autorisée"
```

mais plutôt :

```text
bundle signé
      ↓
contenu authentifié
      ↓
schéma / parser
      ↓
policy d'intégration
      ↓
valeurs bornées
      ↓
transformation contrôlée
      ↓
configuration persistée
```

**Niveau : Requis.**

---

## 15. A/B, bootloader et récupération après interruption

`update-rs` définit les exigences fonctionnelles liées aux slots et au retour à un système bootable, mais la capacité réelle à récupérer d'une coupure d'alimentation dépend du bootloader et de la plateforme.

Pour garantir les propriétés de disponibilité, l'intégration doit fournir :

- deux slots lorsque nécessaire ;
- un mécanisme de sélection du slot ;
- un bootloader capable de revenir au slot précédent ;
- un mécanisme de health-check ;
- un nombre maximal de tentatives de boot ;
- un état persistant de la mise à jour ;
- un mécanisme de recovery.

**Niveau : Requis** pour les objectifs `REQ-FLW-1` à `REQ-FLW-4`.

---

## 16. Watchdog et health-check

Le daemon ne peut pas, à lui seul, déterminer qu'un système nouvellement installé est réellement opérationnel.

L'intégrateur doit définir :

- quel service constitue le health-check ;
- qui déclenche le health-check ;
- quand il est considéré comme valide ;
- combien de tentatives sont autorisées ;
- qui déclenche le rollback ;
- comment le watchdog interagit avec le bootloader.

**Niveau : Requis** pour un rollback automatique fiable.

---

## 17. Réseau et transport du bundle

La cryptographie du bundle protège son authenticité et sa confidentialité, mais ne fournit pas nécessairement la sécurité du canal de distribution.

Le transport doit être protégé contre :

- DoS ;
- épuisement de stockage ;
- récupération répétée de bundles ;
- serveur compromis ;
- mauvaise distribution ;
- interception de métadonnées ;
- abus de l'API de téléchargement.

Selon l'architecture, TLS avec authentification appropriée peut être utilisé.

> La sécurité du transport ne doit cependant pas être considérée comme le mécanisme principal d'authenticité du bundle : celle-ci doit rester garantie par la signature du bundle.

**Niveau : Recommandé**, pouvant devenir **Requis** selon le modèle de menace.

---

## 18. Limitation des ressources

Un bundle authentique peut malgré tout être volumineux ou provoquer une consommation importante de ressources.

L'intégrateur doit définir des limites adaptées :

- taille maximale d'un bundle ;
- nombre maximal de chunks ;
- taille maximale d'un chunk ;
- espace temporaire disponible ;
- mémoire ;
- CPU ;
- nombre de processus ;
- durée maximale d'exécution du payload.

Ces limites sont particulièrement importantes lorsque l'éditeur ou le canal de distribution ne peut pas être considéré comme une source totalement fiable.

**Niveau : Fortement recommandé.**

---

## 19. Journalisation et audit

Les événements critiques doivent être journalisés et, si nécessaire, protégés contre leur suppression par un attaquant local.

Événements pertinents :

- tentative de mise à jour ;
- bundle accepté/refusé ;
- erreur de signature ;
- erreur TPM ;
- anti-rollback ;
- démarrage/fin de CUP ;
- modification de configuration ;
- rollback ;
- échec de health-check ;
- échec de boot ;
- nettoyage après crash.

Lorsque le niveau de sécurité le justifie, les événements critiques peuvent être envoyés vers un système d'audit distant ou faire l'objet d'un mécanisme de preuve plus fort.

**Niveau : Fortement recommandé.**

---

## 20. Résumé des responsabilités

La séparation suivante doit être conservée dans toute analyse de sécurité :

| Responsabilité | `update-rs` | Intégrateur / plateforme |
|---|:---:|:---:|
| Format du bundle | ✓ | |
| Signature / vérification du bundle | ✓ | |
| Chiffrement du payload | ✓ | |
| KEK protégée par TPM | ✓ / selon provisioning | ✓ provisioning |
| Anti-rollback | ✓ mécanisme | ✓ intégration boot/stockage |
| Jail du payload | ✓ | ✓ configuration Linux |
| Secure Boot SoC | | **✓** |
| Vérification bootloader | | **✓** |
| Vérification kernel | | **✓** |
| Vérification rootfs | | **✓** |
| Protection du kernel contre compromission | | **✓** |
| Protection des MTD | partielle | **✓** |
| Protection physique | | **✓** |
| Provisioning TPM | partiel / spécification | **✓** |
| Authentification du matériel | | **✓** |
| Protection clé privée éditeur | | **✓** |
| CI/CD et supply chain | | **✓** |
| Politique des fichiers système modifiables | | **✓** |
| Health-check produit | | **✓** |
| Watchdog / recovery | | **✓** |
| Politique de transport | | **✓** |
| Monitoring opérationnel | | **✓** |

---

## 21. Position de sécurité à retenir

`update-rs` doit être considéré comme **un composant de la chaîne de confiance**, et non comme la chaîne de confiance complète.

La garantie cible peut être représentée ainsi :

```text
                    ┌──────────────────────────┐
                    │ Sécurité physique        │
                    │ + anti-debug             │
                    └────────────┬─────────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │ ROM / SoC Secure Boot    │
                    └────────────┬─────────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │ Bootloader vérifié        │
                    └────────────┬─────────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │ Kernel / rootfs vérifiés  │
                    └────────────┬─────────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │ Linux durci               │
                    │ LSM / permissions / ACL   │
                    └────────────┬─────────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │ update-rs                 │
                    │ signature + TPM + jail    │
                    └────────────┬─────────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │ CUP / policy d'intégration│
                    │ parsing → validation →    │
                    │ transformation → écriture │
                    └────────────┬─────────────┘
                                 ↓
                    ┌──────────────────────────┐
                    │ État persistant vérifié   │
                    └──────────────────────────┘
```

**Conclusion :** une analyse EBIOS ou une architecture produit ne doit pas attribuer à `update-rs` des garanties qui appartiennent aux couches supérieures ou inférieures. En particulier, la mention d'un **Secure Boot dans l'analyse de menace est un prérequis d'architecture**, pas une fonctionnalité fournie par `update-rs`.

