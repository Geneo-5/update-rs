# Comparaison des révisions de la bibliothèque TPM 2.0 (1.59 → 1.84+)

Statut : **Brouillon**
Objet : recenser les révisions de la bibliothèque TPM 2.0 postérieures à la 1.59,
identifier les composants commercialement disponibles et leur niveau de certification
Common Criteria, et évaluer l'impact d'un éventuel changement de révision sur les
primitives mobilisées par le projet. Positionnement : ce document **complète** [`spec/03-tpm.md`](./spec/03-tpm.md) et
[`EBIOS-RM-analysis.md`](./EBIOS-RM-analysis.md) § 1.6 (hypothèses matérielles) et § 1.7
(écarts). Il ne définit aucune exigence `REQ-*` et ne produit aucune cotation de risque :
il alimente un futur ADR (`adr/`, modèle `adr/0000-template.md`).

> Convention : les références `[n]` sont **locales à ce fichier** (voir § 7) et ne doivent
> pas être confondues avec la numérotation `[[1]]`–`[[7]]` de `EBIOS-RM-analysis.md`.
>
> Périmètre : ce fichier traite de la **spécification** (bibliothèque TCG) et des
> **composants certifiés**. La conduite à tenir vis-à-vis des attaques matérielles
> avancées est hors périmètre (cf. § 1.6 et R15).

---

## 1. Contexte et motivation

### 1.1 Le choix actuel du projet

Le README du dépôt et l'analyse de risque déclarent une cible **TPM 2.0, révision 1.59**
de la spécification TCG. L'analyse cite par ailleurs la bibliothèque en révision
**1.38** (2016) tout en notant que « la plateforme cible implémente la révision 1.59 »
(`EBIOS-RM-analysis.md`, réf. `[[4]]`).

**Constat documentaire n° 1.** Il existe une divergence interne entre la révision
*visée* (1.59, README + hypothèse « TPM intégré ») et la révision *citée comme référence
normative* (1.38). Cette divergence n'est pas un problème technique en soi — les deux
révisions coexistent sur le marché — mais elle doit être tranchée et documentée, car la
révision détermine :

- le jeu de primitives auquel `spec/03-tpm.md` peut raisonnablement se conformer ;
- le profil de protection de référence en vue d'une évaluation (`EBIOS-RM-analysis.md`,
  plan d'action T+52 semaines : « Certification Common Criteria ou ANSSI CSPN ») ;
- la liste des errata applicables.

### 1.2 Pourquoi comparer les révisions

Trois motifs, tous issus de l'analyse existante :

1. **Oracle de déchiffrement** (écart « TPM utilisable comme oracle », question 13 de
   `spec/03`, SS13/SO16, R16). La mitigation proposée consiste à *lier la policy au
   contenu vérifié*, voire à *faire porter la décision par le TPM* (R15). Certaines
   commandes de politique et d'attestation sont précisées différemment entre 1.38 et 1.59 ;
   le choix de révision conditionne donc la formulation de la mitigation.
2. **Réinitialisation et rejeu de mesures** (SS11/SO6, R14 ; SO5, R5). La robustesse de
   `PolicyPCR` et le comportement du module après `TPM2_Clear` sont des points précisés
   par les révisions ultérieures et par les errata.
3. **Épuisement des ressources** (SO10, R12). La gestion des sessions et des séquences,
   et l'existence d'un *resource manager*, relèvent de la spécification et de
   l'implémentation noyau, pas seulement du code Rust.

---

## 2. Chronologie des révisions de la bibliothèque

Le TCG publie la bibliothèque TPM 2.0 par révisions successives, chacune composée de
quatre parties (*Architecture*, *Structures*, *Commands*, *Supporting Routines*). Un
document d'**errata et clarifications** distinct couvre plusieurs révisions à la fois
[2] ; c'est la source principale des différences comportementales, le TCG ne publiant pas
de *changelog* annoté ligne à ligne.

| Révision | Publication | Nature du document | Pertinence pour le projet |
|---|---|---|---|
| **1.38** | 29 sept. 2016 | Première consolidation « Level 0 » largement diffusée ; référencée par le profil de protection ANSSI/TCG [3] | Révision historique, citée comme référence documentaire |
| 1.46 | ~2017–2018 | Révision intermédiaire, errata associés [2] | Non pertinente en soi |
| **1.59** | 2019 | **Révision de base cible du projet** ; supportée par un composant certifié ANSSI récent [4] | **Révision visée par le projet** |
| 1.72 | ~2021 | Révision intermédiaire | Faible |
| **1.83 / 1.84** | ~2022–2024 | Dernières révisions connues du TCG à la date de rédaction ; errata conjoints [2] | À surveiller ; aucun composant CC identifié à ce niveau (§ 4.3) |

**Lecture.** La 1.38 n'est pas « obsolète » : elle reste la référence du profil de
protection ANSSI/TCG [3] et la révision implémentée par plusieurs composants certifiés
[5][9]. La 1.59 est la première révision pour laquelle un visa ANSSI récent existe sur un
composant de la famille concernée [4]. Les 1.83/1.84 sont des révisions de la
*spécification* ; les fabricants montent en révision par mises à jour de micrologiciel
sans nécessairement repasser par une évaluation.

---

## 3. Évolutions fonctionnelles pertinentes pour `update-rs`

### 3.1 Grille de lecture : primitives mobilisées × révision

Le tableau ci-dessous liste les primitives effectivement invoquées dans les
`spec/02`, `spec/03` et `spec/05`, et leur statut par révision. La colonne « statut »
distingue **présente** (commande définie en 1.38), **clarifiée** (comportement précisé
par les révisions ultérieures ou les errata [2][7]) et **ajout optionnel** (commande ou
attribut absent de 1.38).

| Primitive / mécanisme | Rôle dans le projet | 1.38 | 1.59 → 1.84 | Impact |
|---|---|---|---|---|
| `TPM2_VerifySignature` | Vérification de la signature ECDSA P-256 du header (VM1) | Présente | Clarifiée (courbes, encodage des hachés) | Faible |
| Import / déballage d'un blob sous une clé parent | Déballage de la `wrapped_session_key` par la KEK (VM1, VM2) | Présente | Clarifiée (`fixedTPM`, `fixedParent`, hiérarchie de parents) | **Moyen** — la commande exacte reste à confirmer (avertissement de `spec/03`) |
| Index NV + compteur monotique | Anti-rollback (REQ-TPM-3, ER6) | Présents | Clarifiés (attributs NV, `TPM2_NV_Increment`, écriture autorisée) | **Moyen** |
| PCR + `PolicyPCR` | Liaison de la policy à l'état de la plateforme (SO6, R14) | Présente | Clarifiée (banques de hachés, sélection, réinitialisation) | **Élevé** |
| `PolicyAuthorize` | Autorisation de déballage par digest de policy signé | Présente | Clarifiée (rôle d'une autorité de signature, interaction avec les sessions) | **Élevé** — cœur de l'oracle SS13 |
| `PolicyNV` | Conditionnement à une valeur NV (borne de version) | Présente | Clarifiée | Moyen |
| Sessions chiffrées (AEAD) | Protection des commandes sensibles sur le bus (VM1, VM2) | Présente | Clarifiée (paramètres de session, nonces, audit de session) | Moyen |
| Attribut `noDA` | Exemption du verrouillage anti-tentatives (SO10, R12) | Présent | Clarifié (comportement après `TPM2_Clear`) | Moyen |
| `TPM2_Clear` | Réinitialisation (vecteur SO5, R5) | Présente | Clarifiée (état résiduel des index NV et des clés persistentes) | **Élevé** |
| *Resource manager* (`/dev/tpmrm0`) | Libération des sessions/séquences (SO10) | Hors bibliothèque (noyau) | Hors bibliothèque | Moyen — dépendance Linux, pas TCG |
| Algorithmes nationaux (SM2/SM3/SM4) | Non utilisés | Absents | Ajoutés en option | Nul (hors périmètre) |

### 3.2 Ce que les révisions ultérieures apportent réellement

Trois catégories de changements, par ordre d'intérêt pour le projet :

**(a) Clarifications normatives — le gain principal.** Les errata [2] et les révisions
1.59+ [7] lèvent des ambiguïtés sur trois points qui apparaissent tels quels dans les
questions ouvertes du projet :

- le **contenu exact d'une policy** et ce qu'une autorisation par digest signé engage
  (question 13 de `spec/03`, oracle SS13) ;
- la **persistance relative** des index NV, des clés persistantes et de l'état de
  verrouillage après une réinitialisation (SO5, SO6) ;
- le **dimensionnement et le cycle de vie des sessions**, pertinent pour l'épuisement de
  ressources (SO10).

**(b) Durcissement du modèle de menace de la plateforme.** Les révisions ultérieures
précisent les conditions dans lesquelles une mesure de plateforme peut être considérée
comme fiable, et le rôle du lien matériel entre réinitialisation du module et
réinitialisation du système. C'est la traduction normative de la mesure « relier la ligne
de reset du TPM au reset du SoC » figurant au plan d'action de l'analyse (R14).

**(c) Ajouts optionnels non mobilisés.** Nouvelles commandes de politique, algorithmes
optionnels, extensions de contexte. Le projet n'en dépend pas ; leur présence n'est donc
pas un motif de migration, mais leur **absence** en 1.38 peut contraindre une mitigation
à être reportée à un ADR ultérieur.

### 3.3 Écarts identifiés

**Aucun écart bloquant** n'a été identifié entre la 1.59 et les révisions supérieures
pour le sous-ensemble de primitives utilisé. Les primitives du projet (signature,
import/déballage, NV, compteur, PCR, `PolicyAuthorize`, `PolicyPCR`, sessions chiffrées)
existent toutes en 1.38 et 1.59. Les révisions ultérieures **précisent** sans **supprimer**.

**Risques résiduels du maintien en 1.59**, à consigner dans l'ADR :

1. **Errata non appliqués.** La 1.59 fait l'objet d'un document d'errata [2]. Un
   composant peut être conforme à la 1.59 *sans* les clarifications ultérieures (1.72+), ce qui
   introduit des divergences d'interprétation entre fabricants sur les points (a) du
   § 3.2 — précisément ceux où le projet a des questions ouvertes.
2. **Vulnérabilités d'implémentation de référence.** Des vulnérabilités de corruption
   mémoire ont été documentées dans l'implémentation de référence de la bibliothèque
   (CERT/CC, avis VU#782720, 2023) [10]. Cet avis concerne le *code de référence*, pas une
   révision donnée ; il impose de vérifier, composant par composant, l'application des
   correctifs — y compris sur un composant 1.59.
3. **Divergence documentaire interne.** Cf. § 1.1 : citer la 1.38 comme référence
   normative tout en ciblant la 1.59 créera une question en évaluation.
4. **Obsolescence de la révision au moment de l'évaluation.** Le plan d'action vise une
   certification à T+52 semaines. Entre-temps, le profil de protection ANSSI/TCG peut être
   révisé pour viser une révision supérieure ; un composant 1.59 pourrait alors être
   évalué contre un profil qui ne le couvre plus.

---

## 4. Composants commercialement disponibles et certification Common Criteria

### 4.1 Récapitulatif

| Composant | Fabricant | Interface | Révision bibliothèque | Certification / visa | Niveau d'assurance | Source |
|---|---|---|---|---|---|---|
| SLB9670 (OPTIGA TPM) | Infineon | SPI / I²C | 1.38 | ANSSI-CC-2021/40 | EAL4+ augmenté (AVA_VAN.5, ALC_FLR.2) | [9] |
| ST33TPHF2E / ST33TPHF2ESPI | STMicroelectronics | SPI | 1.38 | ANSSI-CC-2018/41 | EAL4+ augmenté (AVA_VAN.5, ALC_FLR.2) | [5] |
| ST33GTPMAI2C | STMicroelectronics | I²C | 1.38 / 1.59 selon configuration | (à confirmer) | — | [11] |
| NPCT75x / NPCT7xx | Nuvoton | SPI / I²C | **1.59** (config. 1.3.2.2) | ANSSI-CC-2024/10 | EAL4+ augmenté (AVA_VAN.5) | [4] |
| ATTPM20 | Microchip | I²C | 1.38 | FIPS 140-2 (pas de visa CC ANSSI identifié) | — | [12] |
| SLB9672 | Infineon | SPI / I²C | ≥ 1.38 | FIPS 140-3 (pas de visa CC ANSSI identifié) | — | [13] |

> ⚠️ Les niveaux de révision indiqués proviennent des déclarations de fabricants et des
> cibles de sécurité consultées. **À confirmer auprès du fabricant avant tout choix
> définitif** : un même boîtier peut être livré avec des micrologiciels de révisions
> différentes, et la révision effective est un attribut de la *configuration évaluée*, pas
> du composant.

### 4.2 Observations

**(1) La 1.38 reste bien couverte par l'offre certifiée.** Deux composants disposant d'un
visa ANSSI sont en 1.38 [5][9]. Cette information historique est conservée pour les
plateformes déjà déployées à cette révision.

**(2) Le composant cible retenu (NPCT7xx) est certifié à la révision 1.59.** Le visa
ANSSI-CC-2024/10 porte sur une configuration 1.59 [4]. Un composant à ce bénéfice
intègre les clarifications du § 3.2(a) — donc une assise normative plus solide pour les
questions ouvertes 13 (`spec/03`) et les scénarios SO5/SO6.

**(3) Le profil de protection référence la 1.38.** Le profil ANSSI/TCG pour TPM de client
PC [3] mentionne explicitement la bibliothèque 2.0 Level 0 révision 1.38. Un composant
1.59 évalué contre ce profil doit démontrer sa conformité, ce que la cible [4] semble
traiter. **Implication pratique** : en l'état, une évaluation menée contre le profil
actuel est *plus directe* pour un composant 1.38, mais un composant 1.59 certifié peut
démontrer sa compatibilité par rapport au profil.

**(4) Aucun composant certifié CC identifié en 1.83/1.84.** À la date de rédaction, les
révisions 1.83/1.84 ne sont pas associées à un visa ANSSI ou à un certificat CC public.
Migrer à ce niveau reviendrait à perdre le bénéfice d'une évaluation existante. **Absence
de preuve n'est pas preuve d'absence** : un dossier en instruction n'apparaît pas encore
dans les référentiels publics.

**(5) Le niveau AVA_VAN.5 est l'information la plus utile au projet.** Il correspond à une
résistance évaluée face à un attaquant doté d'un potentiel élevé, ce qui couvre une partie
des sources de risque SR3/SR4 de l'analyse (accès physique flash, accès au bus). En
néanmoins, il ne couvre pas les attaques matérielles avancées (R15, § 1.6) : la
certification du module ne dispense pas de l'hypothèse matérielle.

**(6) Le rapport ANSSI-CC-2021/40 documente un précédent directement utile.** Il relève
qu'une double instanciation du module « permet une mise à jour sécurisée » [9]. C'est une
référence à faire valoir dans `spec/03-tpm.md` et dans le futur dossier d'évaluation :
l'usage d'un TPM comme ancre de la chaîne de mise à jour n'est pas une innovation sans
antécédent certifié.

**(7) Interface : SPI ou I²C.** Le projet mentionne « SPI/I2C » (§ 1.6) sans trancher. La
sensibilité du bus diffère (sonde logique, analyseur de protocole — SS5, SO5) et les
sessions chiffrées sont la mitigation spécifiée dans les deux cas. Les composants 1.38
certifiés existent en SPI [5][9] ; l'offre I²C est plus mince côté visa CC [12]. **Ce
point relève d'un ADR distinct** (choix du composant), pas de la comparaison de révisions.

### 4.3 Matrice décisionnelle préliminaire

| Option | Avantages | Inconvénients | Verdict provisoire |
|---|---|---|---|
| **Maintenir 1.59** | Visa récent [4] ; clarifications intégrées ; assise plus solide pour la mitigation de l'oracle (R16) et de SO5/SO6 | Divergence documentaire avec le profil ANSSI/TCG [3] ; compatibilité à démonmer contre le profil actuel | **Retenu à court terme** |
| **Revenir à 1.38** | Conformité directe au profil ANSSI/TCG [3] ; composants certifiés historiques [5][9] ; zéro travail de re-qualification | Errata à appliquer manuellement [2] ; ambiguïtés normatives non levées sur les points (a) § 3.2 ; perte du visa ANSSI-CC-2024/10 | **Historique, pour plateformes existantes** |
| **Viser 1.83/1.84** | Alignement sur la spécification la plus récente | Aucun composant CC identifié ; risque de perdre tout bénéfice d'évaluation | **Écarté** |

---

## 5. Impact sur les décisions du projet

### 5.1 Ce que la comparaison change — et, surtout, ce qu'elle ne change pas

La tentation, après un tel recensement, est de faire de la révision de la bibliothèque un
levier de sécurité. Il convient d'écarter trois lectures erronées, chacune documentée par
l'existant.

**(a) La révision ne résout pas l'oracle de déchiffrement.** L'écart « TPM utilisable comme
oracle » de `EBIOS-RM-analysis.md` § 1.7 et la question 13 de `spec/03-tpm.md` portent sur
la *portée* d'une policy : savoir si le déballage d'une clé de session est conditionné au
bundle considéré ou à une autorité de signature abstraite. C'est une question de
construction de policy, pas de version de la norme. Les commandes de la famille `Policy*`
(`PolicyAuthorize`, `PolicyPCR`, `PolicyNV`, et les variantes liées au contenu de la
commande) figurent dans la partie 3 de la bibliothèque [7] ; leur sémantique exacte et leurs
interactions sont précisées par les errata [2]. Une migration de révision *facilite* la
formulation de la mitigation (ambiguïtés levées), elle ne la *fournit* pas. La décision
relève donc de l'ADR de policy, pas de l'ADR de révision.

**(b) La révision ne résout pas l'absence d'attestation distante.** Le manque de
`TPM2_Quote` (§ 1.7, R5, R14, plan d'action T+12 semaines) n'est pas imputable à une
révision donnée : l'attestation par signature d'un état de PCR est une commande fondamentale
de la bibliothèque [1][7]. Le projet peut l' spécifier dès aujourd'hui ; ce qui manque est
la conception du vérificateur distant et l'enrôlement d'une identité de module, pas la
primitive.

**(c) La révision ne garantit pas la qualité d'implémentation.** Deux composants déclarés à
une même révision peuvent différer sensiblement : les vulnérabilités de corruption mémoire
relevées dans l'implémentation de référence [10] concernent du *code*, pas une révision, et
les errata [2] ne sont pas appliqués uniformément par les fabricants. Le seul indicateur
publiquement comparable reste le niveau d'assurance de l'évaluation — ici AVA_VAN.5 pour les
visas consultés [4][5][9] — qui ne couvre d'ailleurs pas les attaques matérielles avancées
(R15, § 1.6 de l'analyse).

**Conclusion partielle.** Le choix de révision est une décision de **conformité
documentaire et de calendrier d'évaluation**, non une décision de réduction de risque. Elle
doit être prise en conséquence : sobrement, et subordonnée au choix du composant.

### 5.2 Articulation avec les questions ouvertes du projet

| Question du projet | Où elle est posée | Ce que la comparaison de révisions apporte | Décision attendue |
|---|---|---|---|
| Lier la policy de la KEK au header / au bundle | `spec/03` question 13 ; § 1.7 « TPM utilisable comme oracle » ; R16, SO16 | Clarifications de la partie 3 [7] et des errata [2] sur la portée d'une autorisation par digest ; **aucun blocage en 1.59 identifié** | ADR de policy (T+2 semaines), indépendant de l'ADR de révision |
| KEK par device, par famille ou par flotte | `spec/00` question 6 ; R17, R18, R19 ; SO17–SO20 | Rien : la segmentation de clés est un choix d'architecture de provisioning, indépendant de la révision | ADR de provisioning (T+2 à T+4 semaines) |
| Mécanisme « x3 » : trois branches de policy non décrites | § 1.7 « Mécanisme x3 partiellement spécifié » ; REQ-TPM-X1 à X7 | Les révisions ultérieures précisent les interactions entre commandes de politique et sessions [2][7] ; utile pour rédiger les branches sans ambiguïté | Compléter `spec/03` avant T+2 semaines |
| `PolicyPCR` obligatoire et lien reset TPM ↔ reset SoC | R14, SO6 ; plan d'action T+2 semaines | La 1.59 permet déjà de rendre la policy conditionnelle aux PCR ; le durcissement est d'abord une décision de spécification, et le lien matériel relève de la conception physique | ADR de policy + exigence matérielle (cf. § 6) |
| Épuisement des ressources du module (sessions, séquences) | SO10, R12 ; plan d'action T+24 semaines | Indépendant de la révision TCG : la libération des ressources relève du pilote et du *resource manager* du système (`/dev/tpmrm0`), pas de la bibliothèque | Test de saturation sur matériel réel ; gestion RAII dans `update-tpm` |
| Rotation et révocation des clés | § 1.7 « Pas de rotation des clés », « Pas de révocation de clé » ; R9, R11 | Indépendant de la révision ; les index NV et les politiques de compteur existent en 1.38 et 1.59 [1] | ADR de cycle de vie des clés (T+4 semaines) |
| Attestation distante | § 1.7 « Pas d'attestation distante » ; R5, R14 | Indépendant de la révision (cf. § 5.1b) | Spécifier `TPM2_Quote` et le vérificateur (T+12 semaines) |

**Lecture transversale.** Sur les sept questions ci-dessus, **aucune** n'est bloquée par la
révision 1.59. Les révisions ultérieures apportent un confort d'interprétation (§ 5.1a,
ligne « Mécanisme x3 »), pas de nouvelles capacités structurantes. C'est un argument fort en
faveur du maintien à court terme.

### 5.3 Contenu recommandé pour l'ADR « ADR-TPM-revision »

L'ADR devrait être court et factuel, et comporter au minimum :

1. **Déclaration de la révision applicable** et de la révision de référence documentaire,
   avec justification du choix (cf. § 5.5 pour la correction de la divergence actuelle).
2. **Composant retenu ou présélectionné**, avec sa révision effective, son interface
   (SPI / I²C) et son visa éventuel [4][5][9][11][12][13]. À ce jour, le composant concret
   n'est pas tranché par le projet : l'analyse suppose un module « intégré au SoC ou connecté
   via bus sécurisé » (§ 1.6) sans nommer de pièce.
3. **Liste des errata applicables** au sous-ensemble de commandes utilisé, tirée du document
   d'errata [2], avec pour chacun : impact, statut (appliqué / non applicable / à confirmer
   auprès du fabricant).
4. **Vérification de la correction des avis publics** [10] sur le composant retenu, et
   engagement de suivi des avis du fabricant (le niveau ALC_FLR.2 des visas [5][9] est à cet
   égard un indicateur utile).
5. **Analyse de l'adéquation du profil de protection** : le profil ANSSI/TCG consulté est un
   profil *« PC Client Specific »* [3], calibré pour des plateformes clientes. Pour une
   passerelle embarquée ARMv7, cette adéquation doit être discutée explicitement, car elle
   conditionne la crédibilité de la certification visée à T+52 semaines (cf. § 6, limite 6).
6. **Clause de revue** (cf. § 5.4) et critères de bascule vers une révision supérieure.
7. **Ce que l'ADR ne décide pas** : la portée des policies (ADR dédié), la segmentation des
   KEK (ADR dédié), le choix du bootloader et de la chaîne de boot (action T+2 semaines).

### 5.4 Clauses de revue et alignement sur le plan d'action

| Jalon du plan d'action | Lien avec la révision | Clause de revue proposée |
|---|---|---|
| T+2 semaines (policy, KEK, chaîne de boot, `PolicyPCR`) | Aucun blocage identifié | Vérifier que la rédaction des policies ne repose sur aucune interprétation contestée de la 1.59 ; sinon, documenter l'interprétation retenue dans l'ADR |
| T+4 semaines (rotation, révocation, bundle de migration) | Aucun | Confirmer que les index NV et compteurs nécessaires existent sur le composant retenu (capacité NV, nombre d'index) |
| T+12 semaines (`TPM2_Quote`, rotation implémentée) | Aucun (cf. § 5.1b) | Vérifier la présence et la configuration de la racine d'attestation du composant |
| T+24 semaines (tests de saturation, tests matériels) | Indirect | Les résultats de saturation peuvent révéler des limites propres au composant, indépendamment de la révision : consigner l'écart le cas échéant |
| T+52 semaines (certification CC ou CSPN) | **Direct** | Re-vérifier, au lancement du dossier, que le profil de protection de référence n'a pas été révisé vers une révision supérieure [3] ; sinon, évaluer le coût d'une migration de composant avant dépôt |

### 5.5 Correction de la divergence documentaire interne

`EBIOS-RM-analysis.md` cite en référence `[[4]]` la bibliothèque TPM 2.0 en **révision 1.59**
(2019), tout en précisant entre parenthèses que « la plateforme cible implémente la révision
1.59 », alors que le README et l'hypothèse § 1.6 déclarent la 1.59. La formulation est
cohérente, mais une référence croisée à la 1.38 existe dans les annexes et références.

**Recommandation.** Dans la prochaine itération de l'analyse :

- citer la **1.59** comme norme applicable, avec sa date [6] ;
- citer la **1.38 et les révisions antérieures** [1] comme référence documentaire historique,
  en renvoyant au présent fichier pour la comparaison ;
- renvoyer aux errata [2] pour la liste des points d'interprétation à qualifier.

> ⚠️ **Attention à la collision de numérotation.** Dans `EBIOS-RM-analysis.md`, `[[4]]`
> désigne la bibliothèque TCG. Dans le présent fichier, `[4]` désigne le visa
> ANSSI-CC-2024/10. Les deux conventions sont locales à leur document ; tout croisement de
> lecture doit se faire par le titre de la référence, jamais par son numéro.

---

## 6. Limites de ce document

1. **Micrologiciel non auditable publiquement.** Les visas portent sur des *configurations*
   évaluées [4][5][9]. Un même boîtier peut être livré avec des micrologiciels de niveaux
   différents, et un composant peut exposer des extensions non couvertes par son évaluation.
   La révision effective d'un composant donné se confirme auprès du fabricant, pas dans la
   documentation publique.

2. **Révisions 1.83 / 1.84 peu documentées.** Le TCG ne publie pas de *changelog* annoté
   ligne à ligne ; le document d'errata [2] est la source principale des différences
   comportementales. Les affirmations de ce document sur ces révisions se limitent donc à ce
   que les errata permettent d'établir.

3. **Absence de preuve n'est pas preuve d'absence.** Aucun visa CC public associé aux
   révisions 1.83/1.84 n'a été identifié à la date de rédaction. Un dossier en instruction
   n'apparaît pas dans les référentiels publics ; l'écarté § 4.3 doit être réexaminé à
   chaque jalon.

4. **Le composant n'est pas choisi.** La Clearfog Pro est représentée dans le schéma de
   l'analyse avec un module connecté via SPI/I²C ; l'hypothèse § 1.6 couvre indifféremment
   un module intégré ou discret. Ce document compare des révisions, il ne tranche ni
   l'interface ni la pièce. Le choix du composant relève d'un ADR distinct, dont la
   sensibilité du bus (SS5, SO5) et la protection physique (R15) sont des entrées propres.

5. **La comparaison ne mesure pas la résistance.** AVA_VAN.5 [4][5][9] est un niveau
   d'assurance d'évaluation, pas une garantie contre une classe d'attaques matérielles. Le
   présent document ne permet pas de classer des composants entre eux sur ce critère.

6. **Adéquation du profil de protection.** Le profil consulté est un profil *« PC Client
   Specific »* [3]. Son application à une passerelle embarquée est une approximation qu'un
   futur dossier d'évaluation devra justifier ou remplacer (profil embarqué, CSPN, ou cible
   sur mesure). Cette limite pèse directement sur le réalisme du jalon T+52 semaines.

7. **Aucun audit de code tiers.** Les remarques sur les dépendances (`tss-esapi`,
   `tpm2-tss`, toolchain croisée) renvoient à l'analyse existante (SS7, SO13, R10,
   REQ-CRY-2) ; ce document ne les instruit pas.

---

## 7. Références

*Références locales à ce fichier. Ne pas confondre avec la numérotation `[[n]]` de
`EBIOS-RM-analysis.md` (cf. § 5.5).*

- [1] TCG, *TPM 2.0 Library Specification, Part 1: Architecture*, Level 0, révision 1.38,
  29 septembre 2016.
  https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-1-Architecture-01.07-2014-03-13.pdf
  *(le PDF archivé porte l'en-tête 01.07 ; la référence normative 1.38 est le document
  « Version 2.0, Revision 1.38 » du 29 septembre 2016, distribué par le TCG)*

- [2] TCG, *Errata and Clarifications for TPM Library Specification 2.0*, couvrant les
  révisions 1.16, 1.38, 1.59, 1.83 et 1.84.
  https://trustedcomputinggroup.org/resource/errata-for-tpm-library-specification-2-0/
  https://trustedcomputinggroup.org/wp-content/uploads/TPM2.0-Library-Spec-1.38-Errata-1.13_Pub.pdf

- [3] ANSSI / TCG, *Protection Profile — PC Client Specific Trusted Platform Module*,
  référence ANSSI-PP-2021/02, 29 septembre 2021 (mentionne « TPM Library 2.0 level 0
  revision 1.38 »).
  https://www.commoncriteriaportal.org/nfs/ccpfiles/files/ppfiles/anssi-profil-pp-2021_02en.pdf

- [4] ANSSI, *Cible de sécurité ANSSI-CC-2024/10* — NPCT7xx TPM 2.0, révision 1.59,
  configuration 1.3.2.2 (AVA_VAN.5).
  https://messervices.cyber.gouv.fr/visas/ANSSI-CC-2024-10-cible.pdf

- [5] ANSSI, *Rapport de certification ANSSI-CC-2018/41* — STMicroelectronics ST33TPHF2E,
  TPM 2.0, révision 1.38 (EAL4+ augmenté, AVA_VAN.5, ALC_FLR.2).
  https://www.commoncriteriaportal.org/nfs/ccpfiles/files/epfiles/anssi-cc-2018_41fr.pdf

- [6] TCG, *iTPM 2.0 Library Specification*, révision 1.59, 2019 (annonce et périmètre).
  https://embeddedcomputing.com/technology/security/software-security/tcg-releases-itpm-2-0-library-specification-revision-1-59

- [7] TCG, *TPM 2.0 Library Specification* — Parties 1 à 4, révisions 1.59 et ultérieures
  (1.83, 1.84).
  https://trustedcomputinggroup.org/resource/tpm-library-specification/

- [8] TCG / GitHub, *Implémentation de référence de la bibliothèque TPM 2.0*.
  https://github.com/TrustedComputingGroup/TPM

- [9] ANSSI, *Rapport de certification ANSSI-CC-2021/40* — Infineon SLB9670 (OPTIGA TPM),
  TPM 2.0, révision 1.38 ; relève qu'une double instanciation du module « permet une mise à
  jour sécurisée ».
  https://messervices.cyber.gouv.fr/visas/ANSSI-CC-2021-40-rapport.pdf

- [10] CERT/CC, *VU#782720 — des implémentations TPM 2.0 du TCG vulnérables à une corruption
  mémoire*, 28 février 2023.
  https://kb.cert.org/vuls/id/782720

- [11] STMicroelectronics, *ST33GTPMAI2C* — TPM 2.0 à interface I²C.
  https://www.st.com/en/secure-mcus/st33gtpmai2c.html

- [12] Microchip, *ATTPM20* — TPM 2.0 à interface I²C ; pilote TPM sur bus I²C pour Linux
  embarqué.
  https://support.microchip.com/s/article/TPM-driver-for-embedded-Linux-for-the-I2C-bus

- [13] Infineon, *OPTIGA TPM* (famille SLB967x, dont SLB9672) — modules TPM 2.0.
  https://www.infineon.com/products/security-smart-card-solutions/optiga-embedded-security-solutions/optiga-tpm

---
