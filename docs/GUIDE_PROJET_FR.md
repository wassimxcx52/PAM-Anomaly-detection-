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
│   ├── generate_benign.py          # génère des sessions bénignes synthétiques
│   ├── commands_dataset/           # entrées/intermédiaires de génération
│   └── out/generated_benign.jsonl  # sessions bénignes générées
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
| **`simulate_sessions.py`** | Pilote (Python + paramiko) qui lance de **vraies** sessions labellisées à travers le Bastion. S'authentifie comme `test-ssh`, navigue le menu de sélection de compte WALLIX, exécute un scénario (attaque ou persona bénin), et écrit une ligne dans `ground_truth.jsonl`. Chaque session commence par `echo TAG:<tag>` pour pouvoir la retrouver dans la télémétrie. Auto-nettoyant. |
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

### 4.3 `dataset_generation/` — côté GÉNÉRÉ

Ordre du pipeline (voir aussi `dataset_generation/README.md`) :

| Étape | Fichier | Rôle |
|---|---|---|
| 1a | **`curate_atomic_redteam.py`** | Récupère les tests Linux d'**Atomic Red Team** et les filtre (auto-nettoyants, non destructifs, sans éditeur interactif) → commandes d'attaque par tactique. |
| 1b | **`curate_gtfobins.py`** | Récupère les 478 binaires **GTFOBins** ; mappe `file-read`→cred_access, `upload`→exfil, `sudo/suid`→privesc ; filtre les commandes qui ouvrent un shell (elles bloqueraient le simulateur). |
| 1c | **`curate_linux_commands.py`** | Construit le contenu **bénin** par persona (commandes Linux courantes) → `persona_commands_curated.json`. |
| 2 | **`build_calibration.py`** | Joint les sessions RÉELLES (`feature_extraction/out/`) à la vérité terrain pour extraire, par persona, la fréquence réelle des familles de commandes → `real_benign_calibration.json`. |
| 3 | **`build_persona_weights.py`** | Construit un vocabulaire **pondéré** par persona : 85 % « cœur » ancré sur le réel + 15 % « queue » du corpus curé → `persona_weighted.json`. Le paramètre `--tail-mass` contrôle la diversité. |
| 4 | **`generate_benign.py`** | Échantillonne ce vocabulaire en sessions bénignes synthétiques → `generated_benign.jsonl`. Le paramètre `--stickiness` contrôle la répétition des commandes (réalisme). Même schéma que `sessions.jsonl` réel. |

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

---

## 9. Les features (transform.py)

**Extraites (brutes) :** timestamp, source_ip, target_ip, user, account,
target_name, protocol, command, rule_id, rule_level.

**Calculées (implémentées) :** `command_entropy` (Shannon), `command_count`,
`unique_command_ratio`, `avg_command_length`, drapeaux de risque
(privesc/cred_access/persistence/log_tamper/recon/exfil).

**Calculées (à venir, contextuelles) :** `off_hours_flag`,
`session_hour_zscore`, `duration_zscore` (baseline Welford par utilisateur),
`distinct_targets_24h`, `sessions_count_24h`, `new_source_ip_for_user`,
`distinct_source_ips_24h`, `source_ip_entropy`, `role_command_mismatch`,
`fail_ratio`, `consecutive_failures`, `concurrent_sessions`.

> Principe de diversité : le bénin doit **recouvrir** l'attaque sur chaque axe
> (certaines sessions bénignes sont hors-heures, depuis une IP itinérante, etc.).
> Le signal vient de la **cohérence**, pas d'un seul axe — sinon un axe devient un
> proxy du label et le modèle apprend les métadonnées, pas le comportement.

---

## 10. Métriques d'évaluation

| Métrique | Pourquoi |
|---|---|
| **precision@k** | k = budget d'alertes du SOC. **La** métrique principale, PAS le ROC-AUC (trompeur en fort déséquilibre). |
| **Rappel par tactique** | Quelles tactiques les règles couvrent vs le ML. |
| **Test de McNemar** | Test statistique apparié entre « ML seul » et « règles seules » (cellules discordantes) → une p-value, pas une impression. |
| **Matrice 2×2** | Par session : (règle se déclenche ou non) × (ML signale ou non). La cellule « ML seul » = la thèse ; la cellule « aucun » = la limite honnête. |

**Rappel important :** *Risque ≠ anomalie.* Risque = score d'anomalie × poids
d'impact (criticité de l'actif, fourni par la Sécurité, pas par WALLIX).

---

## 11. Contraintes de laboratoire (documentées, non masquées)

- **Deux hôtes cibles seulement** → pas de vrai mouvement latéral ; on ne
  synthétise pas de faux mouvement latéral.
- **Une seule IP source réelle** → les features d'IP viennent d'un pool
  synthétique ; les deux cibles doivent voir du bénin ET de l'attaque (l'hôte ne
  doit pas devenir un proxy du label).
- **5 comptes réels** tiennent lieu de personas → les baselines « par
  utilisateur » sont en réalité « par persona ». Limite de validité externe
  assumée dans le rapport.
- **Jeu de données semi-synthétique** → doit être documenté comme tel.

---

## 12. Pour démarrer (côté data/IA)

```powershell
# 1. Dépendances
pip install -r requirements.txt

# 2. Régénérer le côté généré (depuis dataset_generation/)
cd dataset_generation
python build_calibration.py          # calibration depuis les données réelles
python build_persona_weights.py      # vocabulaire pondéré
python generate_benign.py --per-persona 250 --stickiness 0.35

# 3. Calculer les features (depuis feature_extraction/)
cd ../feature_extraction
python transform.py                  # → out/features.csv
```

**Prochaines étapes :** couche de métadonnées (utilisateurs synthétiques, pool
d'IP, horodatages, durées) → générateur d'attaques → transform.py enrichi
(features contextuelles) → `rule_baseline.py` (premier chiffre Pool A/B) →
bake-off ML → RAG + API.
