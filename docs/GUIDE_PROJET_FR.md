# Guide du projet — Détection d'anomalies comportementales sur les sessions à privilèges

> Document d'accueil destiné à toute personne rejoignant le projet (ingénieur
> sécurité, ingénieur data/IA). Il explique **la structure du dépôt**, **le rôle
> de chaque fichier**, **les personas**, et **les deux approches de Machine
> Learning** (non supervisée et supervisée) avec leurs métriques.
>
> Décisions verrouillées : voir `docs/decision_log.md`. (Le contexte technique
> détaillé est maintenu dans un document de travail local, hors dépôt.)

---

## 1. Le projet en une phrase

**WALLIX Bastion (PAM) → Wazuh (SIEM) → pipeline de features → scoring ML
d'anomalies → copilote SOC (RAG) → API FastAPI (`/score`, `/ask`) → tableau de
bord.**

L'objectif de recherche est de **démontrer que les règles de détection
configurées dans Wazuh ne suffisent pas**, et que le Machine Learning apporte une
valeur réelle en détectant des comportements que les règles ne peuvent pas voir.

---

## 2. La chaîne de données (vue d'ensemble)

```
   Utilisateur (test-ssh)
        │  se connecte via SSH
        ▼
   WALLIX Bastion  ──────────────  enregistre CHAQUE frappe clavier (KBD_INPUT)
   (192.168.1.50)                  et l'envoie en syslog
        │
        ▼
   Wazuh (SIEM/XDR)  ────────────  décodeur + règles → archives (chaque commande)
   (Docker, 192.168.1.32)
        │
        ▼
   feature_extraction/  ─────────  extract.py  → sessions.jsonl (sessions brutes)
                                   transform.py → features.csv  (features calculées)
        │
        ▼
   Modèles ML  ──────────────────  non supervisé (comportement) + supervisé (type)
```

**Principe fondateur du jeu de données :** *les données GÉNÉRÉES entraînent ; les
sessions RÉELLES jugent ; on ne mélange jamais les deux.* C'est la règle
d'intégrité d'évaluation.

---

## 3. Structure du dépôt

```
hps/
├── README.md
├── requirements.txt
│
├── infra/wazuh/               # couche SIEM (propriété : Sécurité)
│   ├── wallix_decoder.xml      #   décode les lignes syslog WALLIX en champs
│   └── wallix_rules.xml        #   règles de détection (100500-100599)
│
├── feature_extraction/        # côté RÉEL : collecte + pipeline de features
│   ├── simulate_sessions.py    #   pilote de vraies sessions à travers le Bastion
│   ├── extract.py              #   extrait les événements Wazuh → sessions.jsonl
│   ├── extract_raw.py          #   dump brut de diagnostic
│   ├── transform.py            #   calcule les features → features.csv
│   └── out/                    #   sorties réelles (sessions, events, features, GT)
│
├── dataset_generation/        # côté GÉNÉRÉ : construction du jeu synthétique
│   ├── curate_atomic_redteam.py    # commandes d'attaque (Atomic Red Team)
│   ├── curate_gtfobins.py          # commandes d'attaque (GTFOBins)
│   ├── curate_linux_commands.py    # commandes bénignes (contenu personas)
│   ├── build_calibration.py        # statistiques réelles pour calibrer
│   ├── build_persona_weights.py    # vocabulaire pondéré par persona
│   ├── metadata/                   # la couche de métadonnées (organisation synthétique)
│   │   ├── build_identity_pool.py  #   génère l'organisation
│   │   └── identity_pool.json      #   16 utilisateurs, 20 cibles, IP, horaires
│   ├── command_safety.py           # filtre de sûreté partagé (collecte + génération)
│   ├── generate_benign.py          # génère des sessions bénignes synthétiques
│   ├── commands_dataset/           # entrées/intermédiaires de génération
│   └── out/generated_benign.jsonl  # sessions bénignes générées
│
├── ml/
│   ├── unsupervised/          # piste NON SUPERVISÉE (opérationnelle)
│   │   ├── build_eval_set.py   #   jointure vérité-terrain ↔ sessions → eval_real.jsonl
│   │   ├── train.py            #   porte de domaine + bake-off PyOD + precision@k
│   │   └── out/                #   domain_gate.csv, bakeoff_*.csv, eval_scores_*.csv
│   └── supervised/            # piste SUPERVISÉE (pas encore commencée)
│
├── visualisation/             # figures du rapport (PNG + PDF)
│   ├── plot_unsupervised.py    #   relit les artefacts de train.py, ne recalcule rien
│   └── fig1..fig5              #   voir visualisation/README.md
│
└── docs/
    ├── decision_log.md         # décisions durables et verrouillées
    └── GUIDE_PROJET_FR.md       # ce document
```

Deux dossiers-clés, **volontairement séparés** :

- **`feature_extraction/`** = le côté **RÉEL** (« qui juge »). `simulate_sessions.py`
  génère de vraies sessions à travers WALLIX ; c'est le jeu d'évaluation.
- **`dataset_generation/`** = le côté **GÉNÉRÉ** (« qui entraîne »). Sessions
  synthétiques construites à partir de contenu réel.

---

## 4. Explication de chaque fichier

### 4.1 `infra/wazuh/` — couche de détection SIEM

| Fichier | Rôle |
|---|---|
| **`wallix_decoder.xml`** | Transforme une ligne syslog WALLIX brute (`sshproxy[...]: [SSH Session] session_id="..." user="..." data="cat /etc/shadow"`) en champs structurés : `srcuser`, `dstuser`, `command`, `session_id`, etc. Toutes les regex sont en `pcre2`. |
| **`wallix_rules.xml`** | Règles de détection sur ces champs, plage 100500-100599. Chaque règle détecte une **tactique** MITRE ATT&CK par mots-clés (voir §5). Exemple : `100510` = accès aux identifiants (`/etc/shadow`), niveau 12. |

> Ces deux fichiers sont la version « source de vérité ». Une copie identique est
> montée dans le déploiement Docker Wazuh (à synchroniser manuellement).

### 4.2 `feature_extraction/` — côté RÉEL

| Fichier | Rôle |
|---|---|
| **`simulate_sessions.py`** | Pilote (Python + paramiko) qui lance de **vraies** sessions labellisées à travers le Bastion. S'authentifie comme `test-ssh`, navigue le menu de sélection de compte WALLIX, exécute un scénario (attaque ou persona bénin), et écrit une ligne dans `ground_truth.jsonl`. Chaque session commence par `echo TAG:<tag>` pour pouvoir la retrouver dans la télémétrie. Auto-nettoyant. **Compose** les sessions plutôt que de rejouer des listes fixes — voir §4.4. |
| **`extract.py`** | Récupère les événements WALLIX depuis l'**indexeur** Wazuh (OpenSearch, port 9200), les normalise, et produit `events.jsonl` (événements bruts) et `sessions.jsonl` (regroupés par session avec la liste des commandes). Mode append + dédup. Source = **archives** (chaque commande), pas seulement les alertes. |
| **`extract_raw.py`** | Outil de diagnostic. Dump brut, sans transformation, de ce que l'indexeur contient. Sert à répondre à « quels rule_id se déclenchent ? », « à quoi ressemble une ligne non décodée ? ». |
| **`transform.py`** | Calcule les **features** à partir de `sessions.jsonl` → `features.csv`. Version actuelle : `command_count`, `unique_command_ratio`, `avg_command_length`, `command_entropy` (Shannon), et 6 drapeaux de mots-clés à risque. Normalise les tokens de frappe WALLIX (`<NL>`, `<TAB>`, `<BACKSPACE>`). |

**Sorties `feature_extraction/out/` :**

| Fichier | Contenu |
|---|---|
| `ground_truth.jsonl` | La **vérité terrain** : une ligne par session réelle (tag, scénario, `kind` benign/attack, `expected_rule_ids`, MITRE, statut). C'est le seul endroit qui sait ce qu'était réellement chaque session. |
| `sessions.jsonl` | Sessions réelles regroupées (commandes, horodatages, durée). |
| `events.jsonl` | Événements normalisés bruts. |
| `features.csv` | Matrice de features (entrée des modèles). |
| `eval_real.jsonl` | Le **jeu d'évaluation isolé** : sessions réelles labellisées, `split=eval`, jamais entraînées dessus (produit par `ml/unsupervised/build_eval_set.py`). |
| `features_eval_real.csv` | Features du jeu d'évaluation. |
| `features_benign.csv` | Features du bénin **généré** (jeu d'entraînement). |

> ⚠️ `extract.py` écrit relativement au **répertoire courant**. Toujours passer
> `--out-dir feature_extraction/out`, sinon un dossier `out/` parasite est créé
> à la racine du dépôt.

### 4.3 `dataset_generation/` — côté GÉNÉRÉ

Ordre du pipeline (voir aussi `dataset_generation/README.md`) :

| Étape | Fichier | Rôle |
|---|---|---|
| 1a | **`curate_atomic_redteam.py`** | Récupère les tests Linux d'**Atomic Red Team** et les filtre (auto-nettoyants, non destructifs, sans éditeur interactif) → commandes d'attaque par tactique. |
| 1b | **`curate_gtfobins.py`** | Récupère les 478 binaires **GTFOBins** ; mappe `file-read`→cred_access, `upload`→exfil, `sudo/suid`→privesc ; filtre les commandes qui ouvrent un shell (elles bloqueraient le simulateur). |
| 1c | **`curate_linux_commands.py`** | Construit le contenu **bénin** par persona (commandes Linux courantes) → `persona_commands_curated.json`. |
| 2 | **`build_calibration.py`** | Joint les sessions RÉELLES (`feature_extraction/out/`) à la vérité terrain pour extraire, par persona, la fréquence réelle des familles de commandes → `real_benign_calibration.json`. |
| 3 | **`build_persona_weights.py`** | Construit un vocabulaire **pondéré** par persona : 85 % « cœur » ancré sur le réel + 15 % « queue » du corpus curé → `persona_weighted.json`. Le paramètre `--tail-mass` contrôle la diversité. |
| 3b | **`metadata/build_identity_pool.py`** | Construit l'**organisation synthétique** → `identity_pool.json` : 16 utilisateurs (dev/dba/admin/auditor), leurs IP de poste « collantes » par sous-réseau d'équipe, leurs comptes vaultés autorisés, leur distribution d'heures de travail (moyenne/écart-type + astreinte), 20 cibles avec groupe/criticité/protocole, et l'affinité persona→groupe de cibles. Déterministe (graine). |
| 3c | **`command_safety.py`** | Le filtre de sûreté, **définition unique** importée par les deux côtés. Voir §4.5. |
| 4 | **`generate_benign.py`** | Échantillonne ce vocabulaire en sessions bénignes synthétiques → `generated_benign.jsonl`, **drapées sur `identity_pool.json`**. Le paramètre `--stickiness` contrôle la répétition des commandes (réalisme). Même schéma que `sessions.jsonl` réel. |

**La couche de métadonnées (étape 3b + 4) — pourquoi elle est indispensable.**
Sans elle, toutes les sessions générées portaient un seul utilisateur (`test-ssh`)
et une IP fixe par persona. Or les features contextuelles
(`session_hour_zscore`, `new_source_ip_for_user`, `distinct_targets_24h`) mesurent
un **écart par rapport à la ligne de base d'une identité** — sans historique par
utilisateur, elles dégénèrent. Chaque utilisateur possède donc, figé une fois pour
toutes : 1–2 IP de poste, 2–4 hôtes habituels (tirés selon l'affinité de son
persona), et sa propre distribution d'heures.

Le bénin porte **volontairement** du bruit sur chaque axe (≈8 % VPN, ≈2 % jump
host, ~15 % hors-heures, quelques week-ends, quelques sessions `p_admin`
légitimes). Sinon « IP inhabituelle » ou « hors-heures » sépareraient à eux seuls
bénin et attaque, et le modèle apprendrait les **métadonnées** au lieu du
comportement (voir §10, principe de recouvrement).

**Honnêteté :** chaque session générée conserve `real_user` / `real_client_ip` /
`real_target_*` à côté des valeurs synthétiques, et les drapeaux
`identity_is_synthetic` / `ip_is_synthetic` / `ts_is_synthetic`. La substitution
reste auditable. Protocole : **SSH uniquement** — le vocabulaire est du shell
Linux, le draper sur un hôte RDP produirait une session impossible.

> **Limite connue :** `generate_benign.py` tire chaque horodatage
> *indépendamment*. Il n'y a donc pas de « journée » d'un utilisateur, et toutes
> les features à fenêtre 24 h (`sessions_count_24h`, `distinct_targets_24h`,
> `distinct_source_ips_24h`, `concurrent_sessions`) sont vides de sens tant que le
> générateur n'émet pas des **timelines par utilisateur**. C'est le prochain gros
> chantier du générateur.

### 4.4 La composition des sessions (collecte)

Le premier bake-off a révélé, **par la mesure**, deux défauts de la façon dont
`simulate_sessions.py` fabriquait ses sessions. Aucun des deux n'était une
propriété du laboratoire — les deux venaient du pilote :

1. **`unique_command_ratio` valait 1.00 dans toutes les sessions réelles.** Une
   session était une liste fixe de commandes distinctes jouée une fois ; un humain
   se répète. La porte de domaine (§7.5) a donc rejeté `unique_command_ratio` et
   `command_entropy` : un modèle entraîné sur du bénin généré aurait signalé
   chaque session réelle **parce qu'elle est réelle**.
2. **Une session d'attaque était à 100 % des commandes d'attaque**, donc
   `avg_command_length` seule atteignait AUC 0.832. Le détecteur lisait
   « commande longue », pas du comportement. `recon` (14,3 caractères en moyenne)
   passait totalement inaperçu.

**Décision : corriger le COLLECTEUR, jamais calibrer le générateur sur un artefact
de script.** Les sessions sont désormais **composées** :

| Composition | Contenu |
|---|---|
| `sampled` (bénin) | longueur variable (4–14) + répétition (`--stickiness`) |
| `full` | le scénario seul — le cas bruyant, conservé pour le gradient d'intensité |
| `diluted` | le scénario **entier**, avec du bénin intercalé entre ses commandes (ordre relatif préservé → les paires créer-puis-supprimer nettoient toujours) |
| `minimal` | 1–2 commandes d'attaque **en lecture seule** enfouies dans une session bénigne (`--bury-rate`) |

**Sûreté :** `minimal` ne pioche que dans `BURIABLE`, en lecture seule par
construction — aucune commande n'y crée d'état, donc une session interrompue avant
son nettoyage ne peut rien laisser derrière elle. Les scénarios qui **créent** de
l'état ne sont jamais fragmentés (`full` ou `diluted` uniquement).

**Effet mesuré sur télémétrie réelle :** l'écart bénin/attaque en
`avg_command_length` est passé de **25,5 à 1,9 caractères**, `unique_command_ratio`
de 1.00 à ~0,77, et **les 5 features passent désormais la porte de domaine**
(contre 3 sur 5 auparavant).

La composition est enregistrée dans `ground_truth.jsonl` (`composition`,
`attack_command_count`, `total_command_count`) : un détecteur qui ne trouve que les
`full` a trouvé le cas facile, et le rapport doit séparer ces rappels au lieu de
les moyenner.

### 4.5 `command_safety.py` — le filtre de sûreté partagé

Une session collectée a exécuté `mv /usr/local/bin/* /opt/bin/` **en root** sur
debian-lab. Aucun dégât — uniquement parce que `/usr/local/bin` était vide. Rien
ne l'avait empêché.

Deux causes cumulées : `curate_linux_commands.py` filtrait le corpus public contre
`wallix_rules.xml` (pour que le bénin ne déclenche pas de règle) mais **jamais
contre la destructivité** ; et le chemin du corpus dans `simulate_sessions.py`
était périmé depuis la restructuration, de sorte que le corpus n'avait jamais été
réellement chargé — le bug s'est révélé au moment où le chemin a été corrigé.

Ce module est la **définition unique**, importée par les deux côtés pour deux
raisons différentes qui exigent la même règle :

- **`simulate_sessions.py` → SÛRETÉ.** Le remplissage bénin s'exécute vraiment, en
  root, sur un hôte partagé.
- **`build_persona_weights.py` → PARITÉ.** Rien n'y est exécuté, donc rien n'y est
  dangereux. Mais si le générateur peut produire une commande que le collecteur ne
  peut plus produire, les deux vocabulaires bénins divergent — et cette divergence
  réapparaît comme un **marqueur de domaine**, une couture entre jeux de données
  déguisée en signal comportemental.

Deux classes bloquées : la **mutation d'état** (`rm`, `mv`, `mkdir`, `chmod`,
`gzip`, `systemctl`, redirections `>`…) et la **non-terminaison** (`free -s 1`,
`tail -f`, `ping` sans `-c`, `watch`, REPL nus). Cette seconde classe est la plus
sournoise : elle bloquerait la session jusqu'au timeout et **tronquerait
silencieusement** la collecte au lieu de planter. 1669 commandes rejetées sur
~3200.

### 4.6 `ml/unsupervised/` — la piste non supervisée

| Fichier | Rôle |
|---|---|
| **`build_eval_set.py`** | Joint `ground_truth.jsonl` à `sessions.jsonl` via le tag → `eval_real.jsonl`, le jeu d'évaluation isolé. Les sessions sans tag ou en `status=error` sont **comptées et rapportées**, jamais écartées en silence. Le drapeau `--composed-only` ne garde que les sessions postérieures au correctif de composition. |
| **`train.py`** | Applique la porte de domaine (§7.5), entraîne le bake-off PyOD (ECOD/COPOD/IForest/HBOS/PCA) + le baseline MAD **obligatoire** sur le bénin généré, score le jeu réel, et sort `precision@k`. Config A (défaut) exclut les `flag_*` ; Config B les garde. |

**Fichiers `commands_dataset/` :**

| Fichier | Contenu |
|---|---|
| `attack_commands_curated.json` | 256 commandes d'attaque, 6 tactiques (source ART + GTFOBins). |
| `persona_commands_curated.json` | Commandes bénignes par persona. |
| `real_benign_calibration.json` | Fréquences réelles par persona (calibration). |
| `persona_weighted.json` | Vocabulaire pondéré prêt à échantillonner. |


---

## 5. Les personas et les comptes vaultés

Un **persona** = un rôle métier simulé. Chaque persona est mappé à un vrai
compte privilégié « vaulté » dans WALLIX, sur la cible `debian-lab`
(192.168.1.74).

| Persona | Compte WALLIX | Droits réels | Rôle métier simulé |
|---|---|---|---|
| **admin** | `bastionsvc` | compte de test non-sudo | administration système générale |
| **dev** | `p_dev` | sudoers **mais PAS NOPASSWD** | développeur (git, python, build) |
| **dba** | `p_dba` | sudoers **mais PAS NOPASSWD** | administrateur base de données |
| **auditor** | `p_audit` | sudoers **mais PAS NOPASSWD** | auditeur (lecture, journaux) |
| *(attaques)* | `p_admin` | **root** (2e mot de passe `lab`) | compte à privilèges élevés |

**Points importants :**

- `p_dev`, `p_dba`, `p_audit` **ne sont pas NOPASSWD** : un `sudo` demande un mot
  de passe que nous n'avons pas. Une tentative d'escalade par ces comptes est donc
  un **vrai signal de « privesc refusé »** — un compte au rôle normal qui tente
  quelque chose auquel il n'a pas droit. C'est un signal d'insider plus réaliste
  qu'une réussite scriptée. Enregistré comme `commands_denied` / `fail_ratio`.
- Les commandes réservées à root (attaques) passent par `p_admin`.
- Les sessions `p_admin` (root) ne doivent **jamais** être injectées brutes dans
  la base RAG (garde-fou de résumé sanitisé).

**Signal d'insider fort :** l'anomalie recherchée n'est pas seulement une IP
inconnue, mais une **IP connue associée à la MAUVAISE identité** (l'IP habituelle
de `p_dev` utilisée pour une session `p_dba`).

---

## 6. Les scénarios d'attaque (tactiques MITRE)

Six tactiques, chacune liée à une règle Wazuh :

| Tactique | Règle | Niveau | MITRE | Exemple |
|---|---|---|---|---|
| **recon** | 100518 | 6 | T1082, T1087 | `whoami`, `netstat`, `nmap` |
| **cred_access** | 100510 | 12 | T1003, T1552 | `cat /etc/shadow`, clés SSH |
| **privesc** | 100512 | 12 | T1548, T1136 | `useradd`, édition sudoers |
| **persistence** | 100514 | 10 | T1053, T1098 | cron, `authorized_keys` |
| **log_tamper** | 100516 | 12 | T1070, T1562 | `history -c`, suppression de logs |
| **exfil** | 100520 | 10 | T1048, T1041 | `scp`, `curl` upload, `nc` |

Tous les scénarios sont **auto-nettoyants** ou en lecture seule.

---

## 7. Les deux approches de Machine Learning

C'est le cœur méthodologique. **Une même session passe dans les deux modèles**,
qui posent deux questions différentes et échouent sur des sessions différentes.

### 7.1 Approche NON SUPERVISÉE — le comportement

> Question : **« cette session est-elle anormale ? »**

- **Entraînement :** sur les sessions **bénignes uniquement**. Le modèle apprend
  la « densité » du comportement normal ; il ne voit **jamais** de label d'attaque.
- **Modèles (bibliothèque PyOD) :** ECOD, COPOD, Isolation Forest, HBOS,
  reconstruction PCA. Baseline obligatoire : z-score MAD.
- **Sortie :** **un score d'anomalie** ∈ [0, 1] par session (ce n'est PAS une
  classe). On classe les sessions par score et on remonte les **top-k** (budget
  d'alertes du SOC).
- **Force :** détecte l'**inconnu** — des attaques que personne n'a labellisées,
  y compris les commandes « aveugles aux règles » (Pool B, voir §8). Il lui suffit
  de savoir que « ce n'est pas normal ».
- **C'est le modèle qui porte la thèse** (pas de labels → pas de circularité).

### 7.2 Approche SUPERVISÉE — le type d'attaque

> Question : **« est-ce une attaque connue, et de quel type ? »**

- **Entraînement :** sur les données **générées** (bénin + attaque, ratio
  **85:15**). Nécessite des labels → uniquement sur le synthétique (les sessions
  réelles servent à juger).
- **Modèles :** Random Forest, Régression Logistique. **SMOTE** pour le
  déséquilibre des classes.
- **Sortie :** deux formes possibles —
  - **binaire** : `P(attaque)` (forme la plus robuste, à faire en premier) ;
  - **multi-label** : un vecteur de tactiques `{cred_access: 0.8, exfil: 0.6, …}`
    — car une vraie session d'attaque enchaîne plusieurs tactiques (multi-label,
    pas multiclasse).
- **Force :** plus précis sur le **connu**. **Faiblesse :** hérite de l'angle mort
  des règles — incapable de signaler un motif jamais vu à l'entraînement.

### 7.3 Le piège à éviter (circularité)

Les **drapeaux de mots-clés** (`flag_cred_access`, etc.) sont une
réimplémentation des règles. Si on les donne comme features à un modèle qui
prédit les tactiques, « le modèle réapprend les règles » et la thèse s'effondre.
→ On exécute donc **deux configurations** :

- **Config A (comportementale seule)** — SANS les drapeaux. **C'est le modèle de
  thèse.** S'il bat les règles, il l'a fait avec de l'information que les règles
  n'ont pas.
- **Config B (+ drapeaux)** — meilleurs chiffres, modèle de déploiement.

### 7.4 Architecture partagée (important pour la réutilisation)

**Une seule matrice de features ; chaque approche est un FILTRE dessus**, pas un
pipeline séparé. `transform.py` calcule toutes les features une fois, sans tenir
compte du label. Des colonnes de métadonnées (`label`, `tactics`, `source`,
`split`, `persona`) accompagnent chaque ligne.

| Approche | Filtre | Colonnes |
|---|---|---|
| Non supervisée (thèse) | `source=generated & label=benign & split=train` | enlève `flag_*` |
| Supervisée | `split=train` | garde tout, `y=label`/`tactics` |
| Évaluation (les deux) | `source=real & split=eval` | jamais entraînée dessus |

**Conséquence :** le travail sur les sessions bénignes sert AUSSI de classe
majoritaire (85 %) pour le supervisé. On le construit une seule fois.

### 7.5 La porte de domaine — étape obligatoire avant tout entraînement

On entraîne sur du **généré** et on évalue sur du **réel**. Ça ne fonctionne que
pour les features dont la distribution **bénigne** est la même des deux côtés.

Toute feature dont le bénin généré et le bénin réel diffèrent est un **marqueur de
domaine** : le détecteur signalerait les sessions parce qu'elles sont réelles, et
le `precision@k` mesurerait la **couture entre les deux jeux de données** au lieu
d'une anomalie.

Chaque feature candidate passe donc un test de **Kolmogorov-Smirnov à deux
échantillons** entre bénin généré et bénin réel. Mesuré, jamais choisi à la main —
même discipline que le partage Pool A/B.

```
feature                  KS avant → après le correctif de collecte
unique_command_ratio     0.943  →  0.210     KEEP
command_entropy          0.687  →  0.174     KEEP
duration_sec_feat        0.267  →  0.189     KEEP
avg_command_length       0.155  →  0.141     KEEP
command_count            0.041  →  0.131     KEEP
```

**⚠️ Son angle mort, à connaître.** La porte compare **bénin contre bénin
uniquement**. Elle ne peut donc pas voir une contamination de la classe
**attaque**. Ça s'est produit : après avoir corrigé le côté bénin, 45 des 58
attaques du jeu d'éval dataient encore d'avant le correctif, et les chiffres
publiés portaient sur une classe attaque à 78 % artefactuelle. D'où
`build_eval_set.py --composed-only`.

**⚠️ Réserve de fuite, à porter au rapport.** La porte lit les labels **bénins**
du jeu d'évaluation. C'est un usage léger de données d'évaluation pour la
sélection de features. Accepté ici parce que l'alternative — livrer des features
qu'on sait être des marqueurs de domaine — est pire, et parce que la porte est
aveugle à la classe attaque sur laquelle elle est notée. Avec plus de bénin réel,
la forme honnête est de réserver une tranche de calibration.

---

## 8. Pool A / Pool B — la démonstration centrale

On passe chaque commande d'attaque à travers les regex des règles Wazuh :

- **Pool A (visible par les règles)** : au moins une règle correspond.
- **Pool B (aveugle aux règles)** : aucune règle ne correspond, mais la commande
  réalise quand même sa tactique. Exemple : `base64 /etc/passwd` lit un fichier
  sensible sans déclencher une règle qui ne cherche que `cat /etc/shadow`.

Le partage est **mesuré** par script, jamais choisi à la main → crédibilité.

```
Rappel des règles sur Pool B = 0   (par construction, aucune règle ne se déclenche)
Rappel du ML sur Pool B      = ?   ← C'EST LA CONTRIBUTION DU PROJET
```

Si le ML détecte des attaques du Pool B, il détecte ce que les règles ne peuvent
structurellement pas voir. C'est « les règles ne suffisent pas », prouvé par les
données.

> **Statut : PAS ENCORE FAIT.** `rule_baseline.py` n'existe pas. Tant qu'il
> n'existe pas, la phrase centrale du projet n'est pas démontrée — il y a un bon
> modèle ML **sans point de comparaison**. C'est la priorité n°1 de la phase
> suivante (§14).

---

## 9. Résultats de la piste non supervisée (2026-08-07)

### Protocole

```
Entraînement : 1000 sessions bénignes GÉNÉRÉES  (aucun label d'attaque, jamais)
Évaluation   :  256 sessions RÉELLES labellisées, toutes post-correctif
                49 attaques / 207 bénignes → taux de base 19,1 %
Config A     : features comportementales seules, SANS les drapeaux de mots-clés
Features     : les 5 candidates, toutes passées par la porte de domaine
```

### Bake-off

| modèle | ROC-AUC | P@25 | **P@50** | lift@50 |
|---|---|---|---|---|
| **PCA** | 0.778 | **0.72** | **0.60** | ×3,13 |
| ECOD | 0.755 | 0.56 | 0.54 | ×2,82 |
| IForest | 0.775 | 0.60 | 0.52 | ×2,72 |
| HBOS | 0.749 | 0.44 | 0.48 | ×2,51 |
| MAD (baseline) | **0.798** | 0.68 | 0.48 | ×2,51 |
| COPOD | 0.719 | 0.36 | 0.42 | ×2,19 |

Classeur aléatoire = 0.191 à tout *k*. À k=50 : 30 attaques trouvées sur 49, pour
20 faux positifs sur 207 sessions bénignes.

**Deux points à défendre :**

- **MAD gagne le ROC-AUC et perd le `precision@k`.** Les deux métriques se
  contredisent sur les mêmes données. C'est une justification **empirique** du
  choix de `precision@k` (§11), pas un argument emprunté à la littérature. Choisir
  le ROC-AUC aurait fait déployer le mauvais modèle.
- **Avant le correctif de collecte, HBOS menait à 0.862.** Cet avantage était
  l'artefact, pas de l'apprentissage. Le chiffre a baissé *parce que l'évaluation
  est devenue honnête* — à écrire tel quel.

### Le résultat structurant : rappel par composition (PCA @k=50)

| composition | n | rappel | IC 95 % | `avg_command_length` |
|---|---|---|---|---|
| `full` | 13 | 0.92 | [0.67 – 0.99] | 41.4 |
| `diluted` | 21 | 0.67 | [0.45 – 0.83] | 25.9 |
| `minimal` | 15 | **0.27** | [0.11 – 0.52] | 19.3 |
| *(bénin)* | 207 | — | — | 19.1 |

Les sessions `minimal` sont à 19,3 contre 19,1 caractères : sur **toutes** les
features de forme de commande disponibles, elles sont indistinguables du bénin.

**Le détecteur attrape le cas bruyant et rate le cas réaliste.** Ce n'est pas un
échec de réglage, c'est une **limite mesurée** — et elle motive directement les
features contextuelles (§10), que le laboratoire ne peut pas fournir côté réel avec
une identité, une IP source et une cible (§12).

Par tactique : `exfil` 0.88 · `recon` 0.67 · `cred_access` 0.62 · `persistence`
0.62 · `privesc` 0.50 · `log_tamper` 0.38.

### Figures

Toutes les figures sont dans `visualisation/`, régénérables par
`python visualisation/plot_unsupervised.py`. Le script **relit les artefacts de
`train.py`** au lieu de recalculer : les figures ne peuvent pas diverger des
chiffres ci-dessus. PNG (diapositives) + PDF (LaTeX).

| Figure | Contenu |
|---|---|
| `fig1_precision_at_k` | Les 6 détecteurs sur tout le budget d'alertes + ligne du classeur aléatoire |
| `fig2_recall_by_composition` | **La figure centrale** — rappel par furtivité, avec IC 95 % |
| `fig3_domain_gate` | KS par feature, avant/après le correctif de collecte |
| `fig4_score_distribution` | Chaque session, par classe, avec le seuil top-50 |
| `fig5_recall_by_tactic` | Rappel par tactique MITRE |

### Réserves

Les intervalles de confiance font 0,3 à 0,4 de large : on connaît la **direction**,
pas la valeur. Il faut 3 à 5× plus de sessions `minimal` avant de citer « 0.27 »
comme un résultat. S'y ajoutent la réserve de fuite de la porte de domaine (§7.5)
et l'absence de comparaison aux règles (§8).

---

## 10. Les features (transform.py)

**Extraites (brutes) :** timestamp, source_ip, target_ip, user, account,
target_name, protocol, command, rule_id, rule_level.

**Calculées (implémentées, par session) :** `command_entropy` (Shannon),
`command_count`, `unique_command_ratio`, `avg_command_length`, `off_hours_flag`,
`is_weekend`, drapeaux de risque
(privesc/cred_access/persistence/log_tamper/recon/exfil).

**Calculées (implémentées, IP par utilisateur) :** premières features
**inter-sessions** — elles décrivent une session par rapport à l'historique de
son identité, pas isolément.

| Feature | Contenu |
|---|---|
| `new_source_ip_for_user` | l'IP n'a jamais été vue pour cet utilisateur |
| `new_source_ip_globally` | l'IP n'a jamais été vue, pour personne |
| `ip_foreign_to_user` | IP **connue globalement mais nouvelle pour cette identité** — le signal d'insider fort |
| `distinct_source_ips_prior` | nombre d'IP distinctes vues avant cette session |
| `distinct_source_ips_24h` | idem sur une fenêtre glissante de 24 h |
| `source_ip_entropy` | entropie de Shannon sur la distribution d'IP de l'utilisateur |

**Aucune fuite temporelle :** chaque session est calculée à partir des sessions
**strictement antérieures** de ce même utilisateur (`as_of` = son propre
`session_start`). Un `groupby` naïf laisserait les sessions futures définir ce
qui était « déjà connu » à l'époque — d'où le parcours ordonné explicite.

> **Résultat de la porte de domaine (mesuré) :** les 6 sont **rejetées** sur le
> réel. Trois comme marqueurs de domaine (`distinct_source_ips_prior` KS 0.846,
> `source_ip_entropy` 0.846, `distinct_source_ips_24h` 0.390), trois comme
> constantes sur le jeu d'évaluation. C'est la contrainte du §12 devenue un
> chiffre plutôt qu'une affirmation. Elles restent valides côté généré
> (16 utilisateurs, 94 IP) et pour la piste supervisée.

**Calculées (à venir) :** `session_hour_zscore`, `duration_zscore` (baseline
Welford par utilisateur), `distinct_targets_24h`, `sessions_count_24h`,
`role_command_mismatch`, `fail_ratio`, `consecutive_failures`,
`concurrent_sessions`.

> Principe de diversité : le bénin doit **recouvrir** l'attaque sur chaque axe
> (certaines sessions bénignes sont hors-heures, depuis une IP itinérante, etc.).
> Le signal vient de la **cohérence**, pas d'un seul axe — sinon un axe devient un
> proxy du label et le modèle apprend les métadonnées, pas le comportement.

---

## 11. Métriques d'évaluation

| Métrique | Statut | Pourquoi |
|---|---|---|
| **precision@k** | ✅ | k = budget d'alertes du SOC : ce que l'analyste peut réellement examiner. `P@k = attaques dans le top-k / k`. **La** métrique principale. |
| **recall@k** | ✅ | La précision seule se triche en étant timide ; le rappel dit ce qu'on rate. |
| **Taux de base + lift** | ✅ | `lift@k = P@k / taux de base`. Un classeur aléatoire obtient le taux de base à tout *k* — sans cette référence, un P@k n'a aucun sens. |
| **ROC-AUC** | ✅ *(secondaire)* | Rapportée, jamais en titre : elle intègre sur tous les seuils, y compris ceux qu'aucun SOC n'utiliserait, et en fort déséquilibre les vrais négatifs — abondants et gratuits — dominent le calcul. |
| **Rappel stratifié** | ✅ | Par composition d'attaque et par tactique. C'est ce qui a transformé « le modèle marche à 61 % » en information exploitable (§9). |
| **KS (porte de domaine)** | ✅ | Métrique de **validité**, pas de performance : une feature est-elle comparable entre généré et réel ? (§7.5) |
| **Test de McNemar** | ❌ | Test apparié entre « ML seul » et « règles seules » → une p-value, pas une impression. Bloqué par `rule_baseline.py`. |
| **Matrice 2×2** | ❌ | Par session : (règle déclenche) × (ML signale). Cellule « ML seul » = la thèse ; cellule « aucun » = la limite honnête. Bloqué par `rule_baseline.py`. |

**Intervalles de confiance.** Sur des effectifs de 13 à 21 sessions par
composition, un rappel ponctuel ne veut pas dire grand-chose. Rapporter un
intervalle de Wilson à 95 % avec chaque chiffre stratifié.

**Rappel important :** *Risque ≠ anomalie.* Risque = score d'anomalie × poids
d'impact (criticité de l'actif, fourni par la Sécurité, pas par WALLIX). Aucune
pondération d'impact n'est appliquée à ce stade.

---

## 12. Contraintes de laboratoire (documentées, non masquées)

- **Deux hôtes cibles seulement** → pas de vrai mouvement latéral ; on ne
  synthétise pas de faux mouvement latéral.
- **Une seule IP source réelle** → les features d'IP viennent d'un pool
  synthétique ; les deux cibles doivent voir du bénin ET de l'attaque (l'hôte ne
  doit pas devenir un proxy du label).
- **5 comptes réels** tiennent lieu de personas → les baselines « par
  utilisateur » sont en réalité « par persona ». Limite de validité externe
  assumée dans le rapport.
- **Jeu de données semi-synthétique** → doit être documenté comme tel.

**La conséquence, désormais chiffrée.** Côté réel il y a **une identité, une IP
source, une cible**. Les features contextuelles (`session_hour_zscore`,
`new_source_ip_for_user`, `distinct_targets_24h`) ne pourront donc **jamais**
passer la porte de domaine (§7.5) sur ce laboratoire — leur distribution réelle est
dégénérée.

Or ce sont exactement les features qui manquent : le détecteur actuel n'utilise que
la **forme des commandes**, et c'est pourquoi il rate 73 % des attaques `minimal`
(§9). Deux commandes enfouies ne changent pas la forme d'une session — elles ne se
trahissent que par le contexte.

Deux façons honnêtes de traiter ça, à choisir explicitement dans le rapport :

- **Option A** — implémenter ces features et les évaluer sur un jeu **généré** tenu
  à l'écart, en déclarant clairement qu'il s'agit d'une expérience distincte
  (« sur données synthétiques, ces features apportent X »), jamais présentée comme
  la preuve principale.
- **Option B** — les implémenter et documenter qu'elles sont inévaluables dans ce
  laboratoire ; section « travaux futurs ».

Dans les deux cas, le résultat principal reste Pool A/B + la comparaison aux
règles, mesurés sur du **réel**.

---

## 13. Pour démarrer (côté data/IA)

Le cycle complet, dans l'ordre des dépendances. **Le labo doit tourner** pour
l'étape 2 (WALLIX `192.168.1.50`, stack Wazuh sur `192.168.1.32`).

```powershell
# 1. Dépendances
pip install -r requirements.txt

# 2. COLLECTE — sessions réelles à travers le Bastion  (labo requis)
python feature_extraction/simulate_sessions.py --attacks all --repeat 6 --benign 120 `
       --attack-accounts p_admin,p_dev,p_dba,p_audit
python feature_extraction/extract.py --source indexer --since 2h --index archives `
       --out-dir feature_extraction/out

# 3. CÔTÉ GÉNÉRÉ — à relancer après toute nouvelle collecte (la calibration bouge)
cd dataset_generation
python build_calibration.py              # calibration depuis les données réelles
python build_persona_weights.py          # vocabulaire pondéré (filtré par command_safety)
python metadata/build_identity_pool.py   # organisation synthétique (identités, IP, cibles)
python generate_benign.py --per-persona 250 --stickiness 0.35
cd ..

# 4. FEATURES — les deux côtés, même code
python feature_extraction/transform.py                          # généré → features_benign.csv
python ml/unsupervised/build_eval_set.py --composed-only        # réel   → eval_real.jsonl
python feature_extraction/transform.py --in feature_extraction/out/eval_real.jsonl `
       --out feature_extraction/out/features_eval_real.csv --no-split

# 5. ENTRAÎNEMENT + ÉVALUATION
python ml/unsupervised/train.py --k 5,10,25,50
```

> **Piège :** après toute nouvelle collecte, il faut **refaire l'étape 3**. Le
> bénin réel change, donc la calibration du générateur devient périmée et l'écart
> réapparaît comme un marqueur de domaine.

---

## 14. Prochaines étapes

**Fait :** couche de métadonnées · composition des sessions · filtre de sûreté ·
jeu d'évaluation isolé · porte de domaine · piste non supervisée complète.

| Priorité | Chantier | Débloque |
|---|---|---|
| **1** | **`rule_baseline.py`** — Pool A/B, couche règle rejouée sur l'éval, matrice 2×2, McNemar | **La thèse elle-même.** Sans lui, il y a un modèle ML sans point de comparaison. |
| **2** | **Plus de sessions `minimal`** (`--bury-rate 0.95`, viser 50–60) | Resserre l'IC de 0.27 à ±0,12 → chiffre publiable. Temps machine, pas temps de développement. |
| **3** | **Timelines par utilisateur** dans `generate_benign.py` | Toutes les features à fenêtre 24 h, aujourd'hui vides de sens. |
| **4** | **Features contextuelles** dans `transform.py` | Le seul levier crédible sur le cas `minimal`. ⚠️ inévaluables sur du réel (§12) → à traiter comme une expérience distincte, clairement étiquetée. |
| **5** | **Audit de fuite** — classifieur sur métadonnées seules | Désamorce l'objection prévisible sur un jeu semi-synthétique. |
| **6** | `generate_attacks.py` (85:15) puis piste supervisée | Le second modèle du rapport. |
| **7** | RAG + API + tableau de bord | — |

**Ce qu'il ne faut PAS faire :** ajouter d'autres modèles PyOD (le meilleur ne bat
qu'à peine un z-score — le levier est dans les features, pas les algorithmes) ;
régler des seuils pour améliorer les chiffres (« le ML tuné a battu les règles non
tunées » est la critique la plus facile en soutenance) ; démarrer le RAG avant
d'avoir la comparaison aux règles.
