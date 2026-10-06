# État de l'art des systèmes de mise à jour sécurisés

Statut : **Brouillon**
Objet : revue de l'existant (recherche + normes) sur les mécanismes de mise à jour
d'embarqué, leurs solutions de robustesse et de sécurisation, et leurs limites.
Positionnement : ce document **complète** [`EBIOS-RM-analysis.md`](./EBIOS-RM-analysis.md)
et les `spec/0X-*.md` ; il ne définit aucune exigence `REQ-*` et ne fait pas d'analyse
de risque. Il sert de socle bibliographique aux ADR et à `spec/07-security-analysis.md`.

> Convention : les références `[[n]]` sont listées en [§ 7](#7-références). La numérotation
> est locale à ce fichier et indépendante de celle des autres documents de `docs/`.

---

## 1. Introduction

La mise à jour d'une plateforme embarquée est un problème **en apparence résolu** — il
existe des cadres normatifs (TCG [[44]], IETF SUIT [[46]], TUF/Uptane [[48]][[49]], Arm PSA
[[50]]), des implémentations industrielles matures (RAUC [[55]], Mender [[56]], SWUpdate
[[57]], Android A/B [[53]]) et des guides nationaux (ANSSI [[36]][[37]][[38]], NIST
[[40]][[41]], NTIA [[42]], NCSC [[62]], NSA [[59]][[61]]). Pourtant la littérature de
recherche converge sur un constat sévère : les systèmes embarqués sont notoirement
difficiles à mettre à jour [[1]], et une attaque réussie sur le firmware peut rendre un
système inutilisable de façon permanente [[40]]. Les études empiriques récentes montrent
que, sur un parc réel d'objets connectés, le processus de mise à jour reste le maillon
faible [[7]][[28]].

Ce décalage entre l'abondance des cadres et la persistance du risque s'explique : chaque
cadre résout **une facette** du problème (l'authenticité, ou la résilience au brick, ou la
confidentialité, ou la robustesse du flux), rarement plusieurs à la fois, et presque jamais
en les ancrant dans le matériel **sans** supposer le reste du système de confiance. C'est
précisément à cette intersection que se situe `update-rs`.

Ce document procède en trois temps : (§ 2) méthodologie de la revue ; (§ 3) état de l'art
thème par thème, en signalant pour chaque approche ses **limites documentées** ; (§ 4)
tableau de synthèse ; (§ 5) positionnement d'`update-rs` ; (§ 6) limites assumées.

---

## 2. Méthodologie de la revue

La revue est organisée par **fonction de sécurité** plutôt que par produit, car c'est la
découpe qui correspond aux valeurs métier de l'analyse EBIOS RM du projet (VM1 intégrité,
VM2 confidentialité, VM3 disponibilité, VM5 isolation). Pour chaque fonction, on retient :

1. les **papiers de recherche** qui proposent une solution et mesurent ses limites ;
2. les **normes et guides reconnus** (ANSSI, NIST, NTIA, BSI, TCG, IETF, Arm, NCSC, NSA) ;
3. les **implémentations de référence** (RAUC, Mender, SWUpdate, Android, TF-M) ;
4. la **classe d'attaque** que l'approche ne couvre pas — c'est cette colonne qui nourrit
   les questions ouvertes des `spec/0X` et les écarts de `EBIOS-RM-analysis.md` § 1.7.

Les attaques de référence utilisées comme fil rouge sont celles documentées dans la
littérature : altération de firmware [[18]], extraction de firmware par moyens matériels
[[24]][[26]], rétro-ingénierie [[27]][[28]], contournement du module de confiance par
réinitialisation/sommeil [[15]], extraction de clés par mémoire froide [[23]], downgrade
d'exécution fiable [[22]], et attaques de mise à jour (rollback, freeze, mix-and-match,
endless data) taxonomisées par TUF/Uptane [[48]][[49]] et SUIT [[46]].

---

## 3. État de l'art

### 3.1 Architectures et cadres de mise à jour (niveau logiciel)

**Ce qui existe.** Le cadre le plus abouti pour dispositifs contraints est **ASSURED**
(Asokan et al., IEEE TCAD 2018), qui inclut tous les acteurs de l'écosystème de mise à
jour et fournit une sécurité de bout en bout, en étant « nettement plus rapide que les
mécanismes existants dans des contextes réalistes » [[1]]. Zandberg et al. prolongent ce
fil pour l'IoT contraint [[2]]. Catuogno et al. font la revue systématique des limitations
posées à la distribution logicielle pour embarqué/IoT et des défis ouverts [[3]] ; Mtetwa &
Tarwireyi proposent une survey dédiée à la sécurité des mises à jour firmware IoT [[4]].
Côté normalisation, **SUIT/RFC 9124** fournit un modèle de manifeste et un modèle de menace
STRIDE avec identifiants de menaces stables (dont `THREAT.IMG.DISCLOSURE`, la
rétro-ingénierie d'image) [[46]], et TUF/Uptane formalisent la résilience à la
compromission du dépôt [[48]][[49]]. Les implémentations Linux embarqué (RAUC, Mender,
SWUpdate) industrialisent signature X.509, slots A/B et rollback [[55]][[56]][[57]].

**Solutions de robustesse proposées.** Fan et al. proposent un schéma à base d'AES-CCM
contre les attaques de contenu et le déni de service [[5]] ; Park présente un FOTA léger
anti-homme-du-milieu pour environnements contraints [[6]] ; Funabiki et al. (LiSB, 2026)
automatisent la mise à jour OTA avec CI/CD et montrent un prototype surpassant les
schémas d'attestation sur TPM en consommation [[8]] ; CASU vise l'évitement de
compromission par mise à jour sécurisée sur embarqué bas coût [[29]].

**Limites documentées.** Ces travaux sont **purement logiciels** : ils supposent que le
point d'extrémité de vérification (le démon de mise à jour) est intègre. Or Cui et al.
montrent dès 2008 que la modification de firmware contourne précisément ce type de garde
logicielle [[18]], et l'analyse empirique d'Andrews et al. sur 50 appareils confirme que
le processus de mise à jour, pas l'algorithme, est le point de rupture [[7]]. LiSB se
positionne explicitement *contre* l'ancrage TPM pour des raisons de coût/consommation
[[8]] — c'est un arbitrage, pas une suppression du risque. Enfin, aucun de ces cadres ne
traite l'**exécution** du payload après installation : une fois signé, le firmware est
tenu pour confiance.

### 3.2 Résilience et robustesse (anti-brick, atomicité, reprise)

**Ce qui existe.** La référence normative est **NIST SP 800-193** (*Platform Firmware
Resiliency*), qui structure la résilience en trois fonctions — **protéger, détecter,
récupérer** — et vise explicitement les attaques potentiellement destructrices sur le
firmware de plateforme [[40]]. NIST IR 8517 énumère 98 scénarios de défaillance matérielle
comme checklist d'exhaustivité [[41]]. Android industrialise la reprise par **slots A/B**
avec bascule atomique [[53]] et **Verified Boot** avec index de rollback [[54]] ; Arm PSA
(TBFU / Security Model) spécifie un compteur d'anti-rollback mis à jour par le Boot ROM
[[50]][[51]] ; Trusted Firmware-M détaille l'usage de compteurs NV pour l'anti-rollback
[[52]]. Le NCSC et l'NSA publient des guides de gestion du firmware déployé et de
mitigations matérielles [[62]][[59]][[60]].

**Limites documentées.** SP 800-193 est un guide d'**architecture de plateforme**, pas un
protocole de mise à jour : il dit *quoi* garantir (protéger/détecter/récupérer) mais laisse
libre le *comment* applicatif [[40]]. Les mécanismes A/B d'Android protègent les slots du
système, **pas** les données persistantes hors rootfs, et ne définissent pas de bout en
bout l'ordre d'écriture/relecture/bascule/incrémentation du compteur — c'est exactement le
« protocole de commit » marqué écart dans `EBIOS-RM-analysis.md` § 1.7 (SO8). L'incrément
du compteur avant la fin de l'écriture « consomme » une version et laisse le slot incomplet
[[52]][[54]].

### 3.3 Ancrage matériel de confiance (TPM, DICE, PSA)

**Ce qui existe.** Le **TCG Guidance for Secure Update of Software and Firmware on
Devices** est le cadre de référence pour ancrer la mise à jour dans un module de confiance,
en s'appuyant sur un démarrage mesuré et l'attestation [[44]]. L'architecture TPM 2.0
définit les primitives utilisées ici : NV Index pour le stockage persistant, compteurs
monotiques, extension de PCR, et verrouillage anti-attaque par dictionnaire [[45]]. La
révision 1.59 de la bibliothèque TPM est celle visée par le profil de protection ANSSI/TCG
[[67]] et par des composants du marché ; la certification ANSSI-CC-2021/40 relève
explicitement qu'une double instanciation de TPM « permet une mise à jour sécurisée » [[72]].
DICE fournit une alternative sans TPM, avec une implémentation de démarrage mesuré
**formellement vérifiée** [[14]]. L'ANSSI publie des exigences de sécurité matérielle pour
plates-formes [[36]] et des profils de protection pour systèmes industriels [[37]][[38]].

**Solutions proposées.** ROTE (Matetic et al., USENIX Sec 2017) réalise une protection
anti-rollback distribuée s'appuyant sur les compteurs monotiques et la NVRAM du TPM [[16]] ;
TALUS/simTPM (Chakraborty et al.) apportent un stockage NV TPM protégé contre le rollback
pour compteurs persistants [[17]]. WolfSSL documente le scellement par politique PCR et la
persistance des secrets à travers les mises à jour légitimes via une clé résidente qui
ré-autorise la politique [[73]].

**Limites documentées — le point critique.** Han et al. (*Subverting Trusted Platform
Module While You Are Sleeping*, USENIX Sec 2018) montrent qu'un attaquant disposant d'un
accès physique peut **soumettre la chaîne de confiance SRTM** en réinitialisant le TPM sans
redémarrer l'hôte et en rejouant des mesures, ce qui défait toute protection reposant sur
les seuls PCR [[15]]. C'est la traduction exacte du scénario SS11/SO6 du projet. De plus,
la spécification TPM impose un verrouillage anti-dictionnaire [[45]] : un compteur ou une
clé protégés par `authValue` deviennent un vecteur de déni de service (SO10). Enfin, le
choix de la révision 1.59 expose aux errata et vulnérabilités d'implémentation
documentées sur la bibliothèque de référence [[67]][[45]].

### 3.4 Confidentialité du payload

**Ce qui existe.** SUIT prévoit le chiffrement des charges utiles, justifié contre la
divulgation et la découverte de vulnérabilités par rétro-ingénierie [[47]][[46]]. Les
mises à jour chiffrées sont supportées par RAUC et SWUpdate [[57]]. L'ANSSI-FR publie
**MLA**, format d'archive Rust pur avec chiffrement, compression, signatures et
hybridation post-quantique, conçu pour le streaming [[65]], présenté au SSTIC 2026 [[66]].
Les guides cryptographiques ANSSI et BSI encadrent le choix des primitives [[33]][[34]][[43]].

**Limites documentées.** La confidentialité logicielle est **fragile quand la clé est sur
l'appareil** : les enquêtes systématiques d'extraction de firmware [[24]][[26]] et les
revues de rétro-ingénierie [[27]][[28]] montrent que l'attaquant qui contrôle l'appareil
lit la mémoire et le stockage. Halderman et al. établissent l'extraction de clés par
attaque à froid [[23]]. Aucune de ces approches ne résout le cas de l'**opérateur légitime
d'un appareil** (SS13/SO16 du projet) : c'est une limite structurelle du modèle, pas un
défaut d'implémentation.

### 3.5 Anti-rollback et fraîcheur

**Ce qui existe.** TUF/Uptane taxonomisent rollback, freeze, mix-and-match et endless data
et imposent des **dates d'expiration** sur toutes les métadonnées pour borner le freeze
[[48]][[49]]. L'anti-rollback matériel repose sur un numéro de version de sécurité signé et
un compteur monotique [[52]][[51]][[16]][[17]]. Chen et al. montrent un downgrade contre
TrustZone, rappelant que la protection n'est forte que du stockage qui soutient le
compteur [[22]].

**Limites documentées.** Les compteurs monotiques traitent le **downgrade**, pas le
**freeze** : un appareil privé de mise à jour reste indéfiniment sur une version vulnérable
sans le savoir — écart « pas de fraîcheur des mises à jour » de `EBIOS-RM-analysis.md`
§ 1.7 (SS8/ER10). Inversement, TUF/Uptane sont logiciels et n'ancrent pas le compteur dans
le matériel. Les deux familles sont rarement combinées.

### 3.6 Isolation et exécution du payload (jail)

**Ce qui existe.** Linux fournit des primitives de sandbox : namespaces, **seccomp-bpf**,
et le LSM **Landlock** pour le contrôle d'accès non privilégié [[63]][[64]] ; la
combinaison Landlock/seccomp est étudiée récemment [[63]]. Wan et al. proposent l'extraction
automatique de règles de sandbox pour conteneurs Linux [[21]]. L'ANSSI codifie des règles
de développement sûr en Rust [[35]].

**Limites documentées.** Les cadres de mise à jour (§ 3.1) **n'isolent pas** l'exécution du
payload : ils supposent le firmware confiance post-installation. Or les évasions de sandbox
(namespaces/seccomp) sont une classe documentée [[21]][[63]], et les attaques TOCTOU sur
chemins existent y compris en exécution sur place [[75]] et contre l'attestation DICE
[[30]]. Le projet traite ce point (ER5/SO2/SO12) avec un jail et `openat2`/`MS_NOSYMFOLLOW`,
mais la robustesse dépend des fonctionnalités noyau disponibles sur ARMv7 (`CLONE_NEWUSER`,
`CLONE_NEWPID` conditionnels).

### 3.7 Chaîne d'approvisionnement

**Ce qui existe.** NTIA publie un cadre volontaire de sécurisation du processus de mise à
jour [[42]] ; l'OpenSSF définit **SLSA** (niveaux d'assurance des artefacts) [[58]] ; la
NSA documente les attaques firmware réelles et leurs mitigations [[59]][[60]] ; l'ANSSI
cosigne les recommandations SBOM et publie des profils de protection [[37]][[38]]. Binarly
taxonomie les attaques BYOVD contre le démarrage sécurisé [[74]].

**Limites documentées.** Ces cadres portent sur le **build et la distribution**, pas sur
l'appareil : un `updated` ou un `bundle-tool` compromis en amont signe/chiffre autre chose
que ce qui a été validé, et seule une chaîne de boot vérifiée le détecterait — écart
« chaîne d'approvisionnement non maîtrisée » et « chaîne de boot incomplète » de
`EBIOS-RM-analysis.md` § 1.7 (SS7/SO13/SO14). La TCB inclut des composants C (`tpm2-tss`,
toolchain croisée), hors de portée du `forbid(unsafe)` Rust [[35]].

### 3.8 Attestation distante

**Ce qui existe.** Kuang et al. font la survey des attaques et contre-mesures de
l'attestation distante IoT [[12]] ; Ankergård et al. couvrent l'attestation logicielle [[13]] ;
Usman et al. proposent **RASUES**, qui intègre l'attestation distante au mécanisme de mise
à jour et aide à mitiger l'altération physique et les attaques TOCTOU [[10]], et **SCUBA**
pour détecter/récupérer les nœuds compromis [[11]]. La NSA étudie l'attestation au bord du
réseau [[61]].

**Limites documentées.** RASUES/SCUBA sont des schémas de recherche, non industrialisés sur
la cible ARMv7 + TPM 2.0 rév. 1.59. Le projet ne spécifie **pas encore** d'`TPM2_Quote` : impossible
de détecter un TPM remplacé ou compromis — écart « pas d'attestation distante »
`EBIOS-RM-analysis.md` § 1.7.

### 3.9 Vérification formelle

**Ce qui existe.** Tao et al. vérifient formellement une implémentation de démarrage mesuré
DICE [[14]] ; Tacchella et al. étendent SUIT avec vérification formelle pour la mise à jour
firmware [[19]] ; Lorch et al. vérifient automatiquement Uptane [[20]] ; le prouveur Tamarin
est l'outil de référence pour l'analyse symbolique de protocoles [[31]]. Regnath et al.
proposent AMSA, signatures Merkle adaptatives pour embarqué, pertinentes pour la
vérification par morceaux [[25]].

**Limites documentées.** La vérification formelle reste coûteuse et porte sur des modèles
(protocole, boot), rarement sur le démon complet avec son noyau et son TPM. Le projet ne la
mentionne qu'en « nice-to-have » (Prusti, Kani) — écart de maturité assumé.

### 3.10 Primitives cryptographiques et bibliothèques

**Ce qui existe.** L'ANSSI publie les règles de choix et dimensionnement des mécanismes
cryptographiques (v3.00, 2026) [[33]] et un guide de sélection où **le chiffrement de clé
SIV et AES-KeyWrap sont recommandés** [[34]] ; le BSI définit AES-GCM-SIV pour AES-128/256
[[43]] ; l'ANSSI-FR maintient MLA et son hybridation post-quantique [[65]][[66]] et publie
ses vues sur la transition post-quantique [[39]].

**Alignement du projet.** `spec/05-crypto.md` retient AES-256-GCM-SIV (AEAD résistant à
l'abus de nonce), AES-KeyWrap pour le déballage de clé de session, ECDSA P-256 via TPM, et
Ed25519/ML-DSA hybride — cohérent avec [[33]][[34]][[43]][[39]]. La dérivation par chunk
(HKDF, entrées publiques) et l'AAD structurée (`bundle_id`, `chunk_index`, `chunk_count`,
`is_last_chunk`, `chunk_data_length`) correspondent au modèle de vérification incrémentale
par arbre/chaînage de [[25]][[65]].

---

## 4. Synthèse : solutions et limites par fonction

| Fonction | Meilleures approches de l'existant | Limite principale documentée | Réf. |
|---|---|---|---|
| Authenticité / intégrité | ASSURED, TUF/Uptane, SUIT, RAUC | point d'extrémité logiciel supposé intègre | [[1]][[2]][[3]][[46]][[48]][[49]][[55]][[18]] |
| Résilience / anti-brick | NIST SP 800-193, Android A/B, PSA | commit non défini de bout en bout ; données hors slot non couvertes | [[40]][[41]][[53]][[54]][[50]][[51]][[52]] |
| Ancrage matériel | TCG secure update, TPM 2.0, DICE, ROTE/TALUS | SRTM subvertible par reset/rejeu de PCR ; verrouillage DA ; révision 1.59 datée | [[44]][[45]][[14]][[16]][[17]][[15]][[67]][[72]] |
| Confidentialité payload | SUIT encryption, MLA, RAUC/SWUpdate chiffrés | fragile quand la clé est sur l'appareil ; opérateur légitime non couvert | [[47]][[46]][[65]][[66]][[57]][[24]][[26]][[23]] |
| Anti-rollback / fraîcheur | compteurs monotiques TPM ; expiration TUF | rollback ≠ freeze ; les deux familles rarement combinées | [[52]][[51]][[16]][[17]][[22]][[48]][[49]] |
| Isolation du payload | Landlock/seccomp/namespaces, Rust ANSSI | les cadres de mise à jour n'isolent pas l'exécution ; dépend du noyau ARMv7 | [[63]][[64]][[21]][[35]][[75]][[30]] |
| Chaîne d'approvisionnement | NTIA, SLSA, NSA, SBOM ANSSI | porte sur le build, pas sur l'appareil ; TCB inclut du C | [[42]][[58]][[59]][[60]][[37]][[38]][[74]] |
| Attestation distante | RASUES, SCUBA, surveys RA | recherche non industrialisée ; absente du projet | [[10]][[11]][[12]][[13]][[61]] |
| Vérification formelle | DICE vérifié, SUIT+formel, Uptane+formel, Tamarin | coûteuse, sur modèles partiels ; « nice-to-have » ici | [[14]][[19]][[20]][[31]][[25]] |
| Primitives crypto | ANSSI v3.00, sélection SIV/KeyWrap, BSI, MLA PQ | dépend de l'implémentation et des bibliothèques | [[33]][[34]][[43]][[65]][[66]][[39]] |

---

## 5. Positionnement : ce que `update-rs` tente d'apporter de plus

La littérature traite la mise à jour sécurisée d'embarqué comme un problème **décomposé** :
les cadres logiciels (ASSURED, TUF/Uptane, SUIT) résolvent l'authenticité et la résilience
du *transport* mais supposent le démon de vérification intègre [[1]][[2]][[3]][[46]][[48]][[49]] ;
les cadres matériels (TCG secure update, TPM 2.0, DICE, PSA) résolvent l'ancrage de la
*chaîne de confiance* mais laissent ouverte la question de l'exécution du payload et de
l'oracle de déchiffrement [[44]][[45]][[14]][[50]][[15]] ; les guides de résilience
(NIST SP 800-193) prescrivent protéger/détecter/récupérer sans imposer de protocole
applicatif [[40]]. **Aucun travail existant ne combine, sur une même plateforme contrainte
(ARMv7 + TPM 2.0 rév. 1.59), (i) un ancrage matériel de l'authenticité *et* de la
confidentialité, (ii) un format streamable à mémoire bornée résistant au rejeu de morceaux,
(iii) une isolation du *parsing* et de l'*exécution* du payload, et (iv) une politique
matérielle liée au contenu vérifié.** C'est l'espace que cherche à couvrir `update-rs`.

Les apports distinctifs, mesurés à l'aune des limites ci-dessus, sont les suivants.

**1. Lier la politique du TPM au header pour supprimer l'oracle (confusion du député).**
Le problème le plus subtil de l'ancrage matériel est que le TPM, en tant que député
privifié, peut être abusé par qui contrôle l'appareil : si la policy de la KEK autorise un
digest de policy signé sans le lier au header, un opérateur légitime déballe la clé de
session de n'importe quel bundle de la flotte — c'est le scénario SS13/SO16, qualifié de
« quasi certain » dans `EBIOS-RM-analysis.md`. La littérature TPM sur la mise à jour
([[44]][[45]][[73]]) documente le scellement par PCR et sa persistance à travers les mises
à jour, mais ne tranche pas la *liaison contenu↔policy* ; Han et al. montrent même que la
seule liaison aux PCR est défaite par reset/rejeu [[15]]. `update-rs` fait de cette liaison
(question 13 de `spec/03-tpm.md`) une exigence de conception : la policy de déballage est
assujettie au header, ce qui rapproche le schéma du modèle « député confus » classique
[[71]] et le rend non-oraculaire pour un porteur de device. **C'est, à notre connaissance,
le traitement le plus explicite de ce problème dans un mécanisme de mise à jour embarqué.**

**2. Un format streamable à clés dérivées par morceau et AAD structurée.**
Contre l'épuisement de ressources (endless data, bombe de décompression — CWE-409 [[70]])
et le réordonnancement/mélange de morceaux (SO15), `update-bundle` dérive une clé par chunk
(HKDF, entrées publiques) et authentifie chaque chunk par une AAD portant `bundle_id`,
`chunk_index`, `chunk_count`, `is_last_chunk`, `chunk_data_length`, avec validation
séquentielle (REQ-BUN-12 à 15). Cela combine le streaming borné de MLA [[65]][[66]] avec la
vérification incrémentale par chaînage/arbre de Regnath et al. [[25]], en refusant toute
allocation pilotée par une valeur non authentifiée avant vérification (SO9) — contrairement
aux cadres qui vérifient le fichier entier après réception [[55]][[56]][[57]].

**3. Isoler le *parsing* du *décideur* : supervisor/worker avec worker sans TPM ni MTD.**
Les cadres logiciels exécutent le parseur avec les privilèges du démon ; un buffer overflow
dans le manifeste devient alors une compromission root (SO1, noté inacceptable). `update-rs`
sépare supervisor (accès TPM/MTD) et worker sandboxé (parsing, IPC limité à un IR validé),
et ajoute le jail d'exécution du payload (namespaces, seccomp, capabilities, securebits,
`MS_NOSYMFOLLOW`, `openat2`, policy machine, sortie contrôlée) [[63]][[64]][[21]]. Cette
défense en profondeur contre la classe « bug de parseur » est renforcée par le choix du
langage : Rust avec `forbid(unsafe)` au niveau workspace et aucune `unwrap`/`panic!` hors
tests, conformément aux règles ANSSI [[35]] — ce que les implémentations C existantes
n'offrent pas.

**4. Combiner compteur monotique matériel *et* fraîcheur de type TUF.**
L'anti-rollback NV TPM ([[45]][[16]][[17]][[52]]) traite le downgrade ; l'expiration signée
des métadonnées ([[48]][[49]]) traite le freeze. `update-rs` spécifie les deux (REQ-TPM-3 +
mécanisme de fraîcheur, R11), plus la vérification du slot booté contre le compteur et un
environnement U-Boot signé/mesuré (SO7) — une combinaison que ni les travaux TPM ni les
cadres TUF ne proposent isolément.

**5. Segmenter la KEK et gérer son cycle de vie à l'échelle d'une flotte.**
La confidentialité ancrée TPM tombe si une KEK unique ouvre toute la flotte (SO19) et si le
re-provisionnement casse l'alignement `kek_id` (SO17/SO20). `update-rs` spécifie KEK par
device ou par famille, bundle de migration, pool de KEK, rotation et liste de révocation
(R17/R18/R19) — une gestion de clés à l'échelle flotte que la littérature de mise à jour
([[1]][[2]][[3]][[46]]) aborde rarement, car elle suppose une autorité de confiance unique.

**6. Un modèle de menace honnêtement borné.**
Conformément à l'impossibilité démontrée de résister à un attaquant physique déterminé
([[15]][[24]][[26]][[23]][[41]]) et aux hypothèses matérielles de `EBIOS-RM-analysis.md`
§ 1.6, `update-rs` déclare hors périmètre le glitching/injection de fautes et la garde
organisationnelle de la clé de signature éditeur, et concentre ses garanties sur les
attaquants réseau, locaux non-root, porteur de bundle et opérateur de device. Cette
délimitation explicite — plutôt qu'une promesse de sécurité absolue — est en soi un apport
de méthode, aligné sur la démarche EBIOS RM [[32]] et sur SP 800-193 [[40]].

**En résumé**, la contribution d'`update-rs` n'est pas un primitive nouvelle mais une
**composition contrainte et ancrée matériellement** : elle ferme, sur une plateforme à budget
faible, l'écart entre « authenticité logicielle » ([[1]][[46]][[48]]) et « ancrage matériel
de la confidentialité et de la décision » ([[44]][[45]][[15]][[71]]), en traitant explicitement
l'oracle de déchiffrement et l'isolation de l'exécution que les travaux existants laissent
ouverts.

---

## 6. Limites assumées et questions ouvertes héritées de l'existant

Ces limites ne sont pas des défauts masqués : elles découlent de l'état de l'art et sont
portées aux écarts de `EBIOS-RM-analysis.md` § 1.7 et aux questions ouvertes des `spec/0X`.

1. **Révision TPM 1.59.** Justifiée par la disponibilité matérielle de la cible ; à consolider
   par ADR que les errata ultérieurs (1.72, 1.83+) ne modifient pas la sémantique exploitée.
2. **Liaison policy↔header et séquencement logiciel.** Tant que la vérification du header
   est séquencée par le logiciel (question 13 de `spec/03`), un saut de test par injection
   de fautes peut présenter un header non authentique (SS12) ; la contre-mesure de fond est
   de faire *porter la décision par le TPM* [[15]][[45]].
3. **KEK par device vs flotte.** Segmentation réduit SO19 mais alourdit la cérémonie de
   provisioning (SO17) ; arbitrage ouvert (question 6 de `spec/00`).
4. **Attestation distante absente.** Impossible, en l'état, de détecter un TPM remplacé ;
   RASUES/SCUBA [[10]][[11]] et `TPM2_Quote` [[61]] sont à spécifier (écart § 1.7).
5. **Vérification formelle non engagée.** Limitée à « nice-to-have » (Prusti, Kani) alors que
   le domaine progresse [[14]][[19]][[20]][[31]].
6. **Dépendances C dans la TCB.** `tpm2-tss`/`tss-esapi` et la toolchain croisée sont hors
   `forbid(unsafe)` [[35]] ; audit des dépendances (REQ-CRY-2) prévu non en place (SO13).
7. **Fonctionnalités noyau ARMv7.** `CLONE_NEWUSER`/`CLONE_NEWPID` conditionnels fragilisent
   le jail (ER5/SO2) [[63]][[64]][[21]].
8. **Modèle de confidentialité.** Opposable aux attaquants sans device légitime, pas à celui
   qui le contrôle (SS13/SO16) — limite structurelle confirmée par [[23]][[24]][[26]].

---

## 7. Références

### Papiers de recherche
- [[1]] N. Asokan, T. Nyman, A.-R. Sadeghi, E.-O. Blass, N. Hackenberg, W. Schröder, T. Tillich, *ASSURED: Architecture for Secure Software Update of Realistic Embedded Devices*, IEEE Trans. CAD, 2018. https://arxiv.org/abs/1807.05002
- [[2]] K. Zandberg et al., *Secure Firmware Updates for Constrained IoT Devices*, IEEE Access, 2019. https://ieeexplore.ieee.org/iel7/6287639/8600701/08725488.pdf
- [[3]] L. Catuogno et al., *Secure Firmware Update: Challenges and Solutions*, Cryptography (MDPI), 2023. https://www.mdpi.com/2410-387X/7/2/30
- [[4]] J. Mtetwa, N. Tarwireyi, *Secure Firmware Updates in the Internet of Things: A survey*. https://www.semanticscholar.org/paper/c945ef19bb8e1d677d3efb9029663f01c6f7a926
- [[5]] Y.-H. Fan et al., *A Secure IoT Firmware Update Scheme Against SCPA and Denial of Service Attacks*, J. Comput. Sci. Technol., 2021. https://www.sciopen.com/article/10.1007/s11390-020-9831-8
- [[6]] C.-Y. Park, *Secure and Lightweight Firmware Over-the-Air Update*, Electronics, 2025. https://www.mdpi.com/2079-9292/14/8/1583
- [[7]] A. Andrews et al., *An analysis of IoT device update mechanisms*, Computers & Security, 2026. https://www.sciencedirect.com/science/article/pii/S0167404826001501
- [[8]] N. Funabiki et al., *A Proposal of Secure and Automated Over-the-Air Firmware Update* (LiSB), 2026. https://pmc.ncbi.nlm.nih.gov/articles/PMC12987191/
- [[9]] A. S. Gedeon, *Secure boot and firmware update on a microcontroller-based platform*, mémoire, 2020. https://static.crysys.hu/publications/files/setit/thesis_bme_Gedeon20bsc.pdf
- [[10]] A. B. Usman et al., *Bridging remote attestation and secure software updates in embedded systems* (RASUES), IJIS, 2026. https://link.springer.com/article/10.1007/s10207-026-01233-1
- [[11]] A. B. Usman et al., *Remote Attestation with Software Updates in Embedded Systems* (SCUBA). https://www.researchgate.net/publication/385434078
- [[12]] B. Kuang et al., *A survey of remote attestation in Internet of Things: Attacks and countermeasures*, Computers & Security, 2022. https://www.sciencedirect.com/science/article/abs/pii/S0167404821003229
- [[13]] S. F. J. J. Ankergård et al., *State-of-the-Art Software-Based Remote Attestation*, Sensors, 2021. https://pmc.ncbi.nlm.nih.gov/articles/PMC7956325/
- [[14]] Z. Tao et al., *A Formally Verified Implementation of DICE Measured Boot*, USENIX Security 2021. https://www.usenix.org/system/files/sec21fall-tao.pdf
- [[15]] S. Han et al., *Subverting Trusted Platform Module While You Are Sleeping*, USENIX Security 2018. https://www.usenix.org/system/files/conference/usenixsecurity18/sec18-han.pdf
- [[16]] S. Matetic et al., *ROTE: Rollback Protection for Trusted Execution*, USENIX Security 2017. https://eprint.iacr.org/2017/048.pdf
- [[17]] D. Chakraborty et al., *TALUS / simTPM: rollback-protected TPM NV storage*, 2019/2023. https://arxiv.org/pdf/2306.03643
- [[18]] A. Cui, M. Stolfo, K. W. Staggs, *When Firmware Modifications Attack: A Case Study of Embedded Exploitation*, NDSS 2008. https://www.ndss-symposium.org/wp-content/uploads/2017/09/03_4_0.pdf
- [[19]] A. Tacchella et al., *Firmware Secure Updates Meet Formal Verification*, ACM, 2026. https://dl.acm.org/doi/10.1145/3754455
- [[20]] R. Lorch et al., *A Comprehensive, Automated Security Analysis of the Uptane OTA Framework*, 2024. https://dl.acm.org/doi/fullHtml/10.1145/3678890.3678927
- [[21]] Z. Wan et al., *Practical and Effective Sandboxing for Linux Containers*, EMSE. https://zhiyuan-wan.github.io/assets/publications/wan_emse_1_sandbox_mining.pdf
- [[22]] Y. Chen et al., *Downgrade Attack on TrustZone*, arXiv:1707.05082, 2017. https://arxiv.org/pdf/1707.05082
- [[23]] J. A. Halderman et al., *Lest We Remember: Cold Boot Attacks on Encryption Keys*, USENIX Security 2008. https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf
- [[24]] T. Chothia et al., *Breaking All the Things: A Systematic Survey of Firmware Extraction Techniques for IoT Devices*, CARDIS 2018. https://tomchothia.gitlab.io/Papers/CARDIS18.pdf
- [[25]] E. Regnath et al., *AMSA: Adaptive Merkle Signature Architecture*, DATE 2020. https://past.date-conference.com/proceedings-archive/2020/pdf/0065.pdf
- [[26]] E. Karincic et al., *Systematic firmware extraction techniques for industrial forensics*, 2026. https://www.sciencedirect.com/science/article/pii/S2665910726000447
- [[27]] A. Katpara et al., *Firmware Reverse Engineering: A Comprehensive Review*, Electronics, 2026. https://www.mdpi.com/2079-9292/15/17/3830
- [[28]] T. Bakhshi et al., *A Review of IoT Firmware Vulnerabilities and Auditing Techniques*, 2024. https://pmc.ncbi.nlm.nih.gov/articles/PMC10821153/
- [[29]] *CASU: Compromise Avoidance via Secure Update for Low-cost embedded devices*, arXiv:2209.00813, 2022. https://arxiv.org/html/2209.00813v1
- [[30]] *A TOCTOU Attack on DICE Attestation*, arXiv:2201.11764, 2022. https://arxiv.org/html/2201.11764v1
- [[31]] S. Meier, B. Schmidt, C. Cremers, *The TAMARIN Prover for the Symbolic Analysis of Security Protocols*, CAV 2013. https://link.springer.com/chapter/10.1007/978-3-642-39799-8_48

### Normes, guides et spécifications
- [[32]] ANSSI, *La méthode EBIOS Risk Manager – Le guide*, v1.5, mars 2024. https://messervices.cyber.gouv.fr/guides/la-methode-ebios-risk-manager-le-guide
- [[33]] ANSSI, *Règles et recommandations concernant le choix et le dimensionnement des mécanismes cryptographiques*, v3.00, 2026. https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-mecanismes-crypto-3.00.pdf
- [[34]] ANSSI, *Guide de sélection d'algorithmes cryptographiques* (SIV et AES-KeyWrap recommandés), v1.0. https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-selection_crypto-1.0.pdf
- [[35]] ANSSI-FR, *Guide to develop secure applications with Rust*. https://anssi-fr.github.io/rust-guide/
- [[36]] ANSSI, *Exigences de sécurité matérielle pour plates-formes x86*. https://messervices.cyber.gouv.fr/documents-guides/anssi-guide-exigences_securite_materielle.pdf
- [[37]] ANSSI, *Profils de protection pour les systèmes industriels*. https://messervices.cyber.gouv.fr/guides/profils-de-protection-pour-les-systemes-industriels
- [[38]] ANSSI, *La cybersécurité des systèmes industriels – Mesures détaillées*, v2, 2025. https://messervices.cyber.gouv.fr/documents-guides/Guide_Systemes_industriels__Mesures_detaillees_v2.pdf
- [[39]] ANSSI, *ANSSI views on the Post-Quantum Cryptography transition*. https://messervices.cyber.gouv.fr/guides/en-anssi-views-post-quantum-cryptography-transition
- [[40]] A. Regenscheid et al., *NIST SP 800-193, Platform Firmware Resiliency Guidelines*, 2018. https://csrc.nist.gov/pubs/sp/800/193/final
- [[41]] P. Mell et al., *NIST IR 8517, Hardware Security Failure Scenarios*, 2024. https://csrc.nist.gov/pubs/ir/8517/final
- [[42]] NTIA, *Voluntary Framework for Enhancing Update Process Security*. https://www.ntia.gov/files/ntia/publications/ntia_iot_security_update_framework.pdf
- [[43]] BSI, *TR-02102-1, Cryptographic Mechanisms: Recommendations and Key Lengths*, 2026-01 (AES-GCM-SIV). https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-1.pdf
- [[44]] TCG, *Guidance for Secure Update of Software and Firmware on Devices*, v1r72, 2020. https://trustedcomputinggroup.org/wp-content/uploads/TCG-Secure-Update-of-SW-and-FW-on-Devices-v1r72_pub.pdf
- [[45]] TCG, *Trusted Platform Module Library, Part 1: Architecture*, révision 1.59. https://trustedcomputinggroup.org/wp-content/uploads/TCG_TPM2_r1p59_Part1_Architecture_pub.pdf
- [[46]] IETF, *RFC 9124, A Manifest Information Model for Firmware Updates in IoT Devices (SUIT)*. https://datatracker.ietf.org/doc/html/rfc9124
- [[47]] IETF, *Encrypted Payloads in SUIT Manifests* (draft-ietf-suit-firmware-encryption). https://datatracker.ietf.org/doc/draft-ietf-suit-firmware-encryption/
- [[48]] TUF, *The Update Framework Specification*. https://theupdateframework.github.io/specification/latest/
- [[49]] Uptane, *Standard for Design and Implementation*, v2.0.0. https://uptane.org/docs/2.0.0/standard/uptane-standard
- [[50]] Arm, *PSA Trusted Boot and Firmware Update* (DEN0072). https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/PSA/DEN0072-PSA_TBFU_1-0-REL.pdf
- [[51]] Arm, *PSA Security Model* (DEN0079), compteur d'anti-rollback Boot ROM. https://armkeil.blob.core.windows.net/developer/Files/pdf/PlatformSecurityArchitecture/Architect/DEN0079_PSA_SM_ALPHA-03_RC01.pdf
- [[52]] Trusted Firmware-M, *Rollback protection in TF-M secure boot*. https://trustedfirmware-m.readthedocs.io/en/latest/design_docs/booting/secure_boot_rollback_protection.html
- [[53]] Android, *A/B (seamless) system updates*. https://source.android.com/docs/core/ota/ab
- [[54]] Android, *Verified Boot* (rollback index). https://source.android.com/docs/security/features/verifiedboot
- [[55]] RAUC, *Safe and Secure OTA Updates for Embedded Linux*. https://rauc.io/
- [[56]] Mender, *OTA updates best practices*. https://mender.io/resources/reports-and-guides/ota-updates-best-practices
- [[57]] Comparatifs d'engines OTA (RAUC/SWUpdate/Mender, mises à jour chiffrées). https://rugix.org/blog/2026-02-28-ota-update-engines-compared/
- [[58]] OpenSSF, *SLSA – Supply-chain Levels for Software Artifacts*. https://slsa.dev/
- [[59]] NSA, *Hardware and Firmware Security Guidance*. https://github.com/nsacyber/Hardware-and-Firmware-Security-Guidance
- [[60]] NSA, *BlackLotus Mitigation Guide*, 2023. https://media.defense.gov/2023/Jun/22/2003245723/-1/-1/0/CSI_BlackLotus_Mitigation_Guide.PDF
- [[61]] NSA, *Trusted Platform Module (TPM) Use Cases*, 2024. https://media.defense.gov/2024/Nov/06/2003579882/-1/-1/0/CSI-TPM-USE-CASES.PDF
- [[62]] NCSC (UK), *Device Security Guidance – Managing deployed devices*. https://www.ncsc.gov.uk/collection/device-security-guidance/managing-deployed-devices/managing-device-firmware
- [[63]] Linux kernel, *Landlock: unprivileged access control*. https://docs.kernel.org/userspace-api/landlock.html
- [[64]] Linux man-pages, *seccomp_unotify(2)*. https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html
- [[65]] ANSSI-FR, *MLA – Multi Layer Archive* (archive Rust streamable, chiffrement, signatures, PQC). https://github.com/ANSSI-FR/MLA
- [[66]] C. Mougey, J. Barallon, *MLA et l'implémentation d'une hybridation cryptographique*, SSTIC 2026. https://www.sstic.org/2026/presentation/mla_et_l_implementation_d_une_hybridation_cryptographique/
- [[67]] ANSSI/TCG, *Protection Profile PC Client Specific TPM* (réf. TPM Library 2.0 rév. 1.59). https://www.commoncriteriaportal.org/nfs/ccpfiles/files/ppfiles/anssi-profil-pp-2021_02en.pdf
- [[68]] Texas Instruments, *SLAA682, Secure In-Field Firmware Updates for MSP MCUs*. https://www.ti.com/lit/slaa682
- [[69]] Open Compute Project / CSIS, *Secure Firmware Development Best Practices*. https://www.opencompute.org/documents/csis-firmware-security-best-practices-position-paper-version-1-0-pdf
- [[70]] MITRE, *CWE-409: Improper Handling of Highly Compressed Data* (décompression bomb). https://cwe.mitre.org/data/definitions/409.html
- [[71]] N. Hardy / AWS, *The confused deputy problem*. https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html
- [[72]] ANSSI, *Rapport de certification ANSSI-CC-2021/40* (double instanciation TPM → mise à jour sécurisée). https://messervices.cyber.gouv.fr/visas/ANSSI-CC-2021-40-rapport.pdf
- [[73]] WolfSSL, *TPM 2.0 Sealing and PCR Policies* (persistance des secrets à travers les mises à jour). https://www.wolfssl.com/tpm-2-0-sealing-policies-with-wolftpm-pcr-policies-policy-authorize-and-nv-storage-for-tpm-2-0-secrets/
- [[74]] Binarly, *Signed and Dangerous: BYOVD Attacks on Secure Boot* (taxonomie). https://www.binarly.io/blog/signed-and-dangerous-byovd-attacks-on-secure-boot
- [[75]] ONEKEY Research, *Making TOCTOU Great Again – X(R)IP* (TOCTOU sur embarqué XiP). https://www.onekey.com/resource/making-toctou-great-again-xrip

---
