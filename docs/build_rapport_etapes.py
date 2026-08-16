#!/usr/bin/env python3
"""
build_rapport_etapes.py -- génère RAPPORT_ETAPES.pdf, le compte rendu pas à pas
des étapes réalisées sur la piste non supervisée.

Le document raconte la séquence RÉELLE, y compris les deux artefacts découverts en
cours de route et l'incident de sûreté — c'est la partie qui a le plus de valeur
pour le rapport de stage, et elle disparaîtrait dans un résumé « tout s'est bien
passé ».

Les figures sont celles de visualisation/ : elles sont produites à partir des
artefacts de train.py, donc rien ici n'est ressaisi à la main.

    python docs/build_rapport_etapes.py

⚠️ INSTANTANÉ DU 2026-08-07, PAS UNE VUE EN DIRECT. Le TEXTE de ce script (les
chiffres cités dans les paragraphes) est figé en dur et antérieur au correctif du
décodeur du 2026-08-15 : relancer le script aujourd'hui régénère un PDF dont la
narration est périmée, avec des figures à jour — la pire combinaison, parce que
l'incohérence ne se voit pas. Avant toute réexécution, reprendre les chiffres
depuis docs/session_2026-08-15_command_rarity.md et ml/results_all.csv.
"""

from __future__ import annotations

import os

from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, Image, KeepTogether,
                                NextPageTemplate, PageTemplate, Paragraph,
                                Spacer, Table, TableStyle)

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, ".."))
VIZ = os.path.join(ROOT, "visualisation")
OUT = os.path.join(HERE, "RAPPORT_ETAPES.pdf")

# palette (identique à visualisation/plot_unsupervised.py)
INK = colors.HexColor("#0b0b0b")
INK_2 = colors.HexColor("#52514e")
MUTED = colors.HexColor("#898781")
BLUE = colors.HexColor("#2a78d6")
BLUE_DARK = colors.HexColor("#184f95")
ORANGE = colors.HexColor("#eb6834")
RULE = colors.HexColor("#e1e0d9")
BAND = colors.HexColor("#f4f4f1")

PAGE_W, PAGE_H = A4
MARGIN = 20 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

_ss = getSampleStyleSheet()


def style(name, **kw):
    base = dict(fontName="Helvetica", fontSize=9.5, leading=14, textColor=INK_2,
                spaceAfter=6)
    base.update(kw)
    return ParagraphStyle(name, parent=_ss["Normal"], **base)


S = {
    "title": style("title", fontName="Helvetica-Bold", fontSize=20, leading=24,
                   textColor=INK, spaceAfter=4),
    "subtitle": style("subtitle", fontSize=10.5, leading=15, textColor=MUTED,
                      spaceAfter=18),
    "h1": style("h1", fontName="Helvetica-Bold", fontSize=13, leading=17,
                textColor=INK, spaceBefore=16, spaceAfter=7),
    "h2": style("h2", fontName="Helvetica-Bold", fontSize=10.5, leading=14,
                textColor=BLUE_DARK, spaceBefore=10, spaceAfter=5),
    "body": style("body", alignment=TA_JUSTIFY),
    "bullet": style("bullet", leftIndent=10, bulletIndent=2, spaceAfter=3),
    "code": style("code", fontName="Courier", fontSize=8, leading=11,
                  textColor=INK, backColor=BAND, borderPadding=6,
                  spaceBefore=4, spaceAfter=8),
    "caption": style("caption", fontSize=8, leading=11, textColor=MUTED,
                     spaceBefore=3, spaceAfter=12),
    "note": style("note", fontSize=9, leading=13, textColor=INK_2,
                  leftIndent=8, borderPadding=0),
}


def para(text, kind="body"):
    return Paragraph(text, S[kind])


def bullets(items):
    return [Paragraph(f"&bull;&nbsp;&nbsp;{t}", S["bullet"]) for t in items]


def callout(title, text, accent=ORANGE):
    """Encadré à filet coloré — pour les découvertes et les réserves."""
    inner = [Paragraph(f"<b>{title}</b>", style("ct", fontName="Helvetica-Bold",
                                                fontSize=9.5, leading=13,
                                                textColor=accent, spaceAfter=4)),
             Paragraph(text, style("cb", fontSize=9, leading=13.5,
                                   textColor=INK_2, spaceAfter=0))]
    t = Table([[inner]], colWidths=[CONTENT_W])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), BAND),
        ("LINEBEFORE", (0, 0), (0, -1), 2.2, accent),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    return [t, Spacer(1, 10)]


def data_table(rows, widths=None, align_right=None, header=True):
    cell = style("cell", fontSize=8.5, leading=11.5, spaceAfter=0)
    head = style("head", fontSize=8.5, leading=11.5, spaceAfter=0,
                 fontName="Helvetica-Bold", textColor=INK)
    body = [[Paragraph(str(c), head if (header and r == 0) else cell)
             for c in row] for r, row in enumerate(rows)]
    t = Table(body, colWidths=widths or [CONTENT_W / len(rows[0])] * len(rows[0]))
    cmds = [
        ("LINEBELOW", (0, 0), (-1, 0), 0.8, RULE if not header else INK_2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, BAND]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for col in (align_right or []):
        cmds.append(("ALIGN", (col, 0), (col, -1), "RIGHT"))
    t.setStyle(TableStyle(cmds))
    return [t, Spacer(1, 10)]


def figure(name, caption, width_frac=1.0):
    path = os.path.join(VIZ, f"{name}.png")
    if not os.path.isfile(path):
        return [para(f"[figure manquante : {name}.png]", "caption")]
    from reportlab.lib.utils import ImageReader
    iw, ih = ImageReader(path).getSize()
    w = CONTENT_W * width_frac
    img = Image(path, width=w, height=w * ih / iw)
    return [KeepTogether([img, para(caption, "caption")])]


def header_footer(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(MUTED)
    canvas.drawString(MARGIN, PAGE_H - MARGIN + 8,
                      "Détection d'anomalies comportementales sur les sessions "
                      "à privilèges")
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - MARGIN + 8, "7 août 2026")
    canvas.setStrokeColor(RULE)
    canvas.setLineWidth(0.6)
    canvas.line(MARGIN, PAGE_H - MARGIN + 4, PAGE_W - MARGIN, PAGE_H - MARGIN + 4)
    canvas.drawCentredString(PAGE_W / 2, MARGIN - 12, str(doc.page))
    canvas.restoreState()


# ------------------------------------------------------------------ contenu ---
def build_story():
    s = []

    s.append(para("Étapes réalisées — piste non supervisée", "title"))
    s.append(para("Compte rendu pas à pas de la journée du 7 août 2026 : ce qui a "
                  "été construit, dans quel ordre, et ce que les mesures ont "
                  "révélé en cours de route.", "subtitle"))

    # ---------------------------------------------------------- point de départ
    s.append(para("Point de départ", "h1"))
    s.append(para(
        "Le pipeline WALLIX &rarr; Wazuh &rarr; extraction fonctionnait, et un "
        "générateur de sessions bénignes synthétiques existait. Mais aucun modèle "
        "n'avait encore été entraîné, et la couche de métadonnées "
        "(<font face='Courier' size='8.5'>identity_pool.json</font>) était "
        "construite sans être consommée par quoi que ce soit : chaque session "
        "générée portait un seul utilisateur et une IP fictive par persona."))

    # ------------------------------------------------------------------ étape 1
    s.append(para("Étape 1 — Brancher la couche de métadonnées", "h1"))
    s.append(para(
        "Réécriture de <font face='Courier' size='8.5'>generate_benign.py</font> "
        "pour draper chaque session synthétique sur une identité réelle du pool. "
        "Chaque utilisateur possède, figé une fois pour toutes : 1 à 2 IP de poste "
        "dans le sous-réseau de son équipe, 2 à 4 hôtes habituels tirés selon "
        "l'affinité de son persona, et sa propre distribution d'heures de travail."))
    s.extend(data_table([
        ["", "Avant", "Après"],
        ["Utilisateurs", "1 (test-ssh)", "16"],
        ["IP clientes distinctes", "4 (placeholder)", "107"],
        ["Cibles", "1", "15"],
        ["Sessions hors-heures", "0 %", "14,6 %"],
    ], widths=[CONTENT_W * 0.4, CONTENT_W * 0.3, CONTENT_W * 0.3],
        align_right=[1, 2]))
    s.append(para(
        "Le bénin porte <b>volontairement</b> du bruit sur chaque axe : 8 % de "
        "sessions VPN, 2 % depuis un serveur de rebond, quelques week-ends, "
        "quelques emprunts légitimes du compte privilégié. Sans ce recouvrement, "
        "« IP inhabituelle » ou « hors-heures » sépareraient à eux seuls le bénin "
        "de l'attaque, et le modèle apprendrait les métadonnées au lieu du "
        "comportement."))

    # ------------------------------------------------------------------ étape 2
    s.append(para("Étape 2 — Construire la piste non supervisée", "h1"))
    s.append(para("Deux scripts, plus une étape méthodologique intercalée."))
    s.append(para("2.1  Le jeu d'évaluation isolé", "h2"))
    s.append(para(
        "<font face='Courier' size='8.5'>build_eval_set.py</font> joint la vérité "
        "terrain aux sessions extraites via le marqueur "
        "<font face='Courier' size='8.5'>echo TAG:</font> — le seul lien possible, "
        "puisque WALLIX attribue un identifiant opaque sans rapport avec le "
        "scénario joué. Les sessions sans marqueur ou en erreur sont "
        "<b>comptées et rapportées</b>, jamais écartées en silence."))
    s.append(para("2.2  La porte de domaine", "h2"))
    s.append(para(
        "On entraîne sur du généré et on évalue sur du réel. Cela ne fonctionne "
        "que pour les features dont la distribution <b>bénigne</b> est la même des "
        "deux côtés. Chaque feature candidate passe donc un test de "
        "Kolmogorov-Smirnov entre bénin généré et bénin réel. Une feature qui "
        "échoue est un <b>marqueur de domaine</b> : le détecteur signalerait une "
        "session parce qu'elle est réelle, et le precision@k mesurerait la couture "
        "entre les deux jeux de données au lieu d'une anomalie."))
    s.append(para("2.3  Le bake-off", "h2"))
    s.append(para(
        "<font face='Courier' size='8.5'>train.py</font> entraîne ECOD, COPOD, "
        "Isolation Forest, HBOS et PCA sur le bénin généré uniquement, plus un "
        "baseline MAD <b>obligatoire</b> (z-score robuste). Configuration A : "
        "features comportementales seules, sans les drapeaux de mots-clés — ces "
        "drapeaux sont une réimplémentation des règles Wazuh, et les fournir au "
        "modèle reviendrait à lui faire réapprendre les règles."))

    # ------------------------------------------------------------------ étape 3
    s.append(para("Étape 3 — Le premier bake-off révèle deux artefacts", "h1"))
    s.append(para(
        "Le premier résultat semblait excellent. Il ne l'était pas : deux défauts "
        "de collecte faisaient que le détecteur lisait des artefacts de script "
        "plutôt que du comportement. Aucun des deux n'a été trouvé par relecture "
        "du code — les deux ont été trouvés <b>par la mesure</b>."))
    s.extend(callout(
        "Artefact n°1 — unique_command_ratio valait 1,00 partout",
        "Une session était une liste fixe de commandes distinctes jouée une seule "
        "fois ; un humain se répète. La porte de domaine a rejeté "
        "<font face='Courier' size='8.5'>unique_command_ratio</font> (KS 0,94) et "
        "<font face='Courier' size='8.5'>command_entropy</font> (KS 0,69) : deux "
        "features sur cinq perdues."))
    s.extend(callout(
        "Artefact n°2 — une attaque était à 100 % des commandes d'attaque",
        "<font face='Courier' size='8.5'>avg_command_length</font> atteignait à "
        "elle seule une AUC de 0,832. Le détecteur lisait « commande longue », pas "
        "du comportement. La tactique <i>recon</i> (14,3 caractères de moyenne) "
        "était indistinguable du bénin et passait totalement inaperçue."))
    s.append(para(
        "<b>Décision : corriger le collecteur, jamais calibrer le générateur sur "
        "un artefact de script.</b> Faire coïncider le générateur avec un "
        "unique_command_ratio de 1,00 aurait appris au modèle que « bénin = toutes "
        "les commandes distinctes », et un utilisateur qui répète une commande "
        "serait devenu anormal pour la mauvaise raison."))

    # ------------------------------------------------------------------ étape 4
    s.append(para("Étape 4 — Corriger le collecteur", "h1"))
    s.append(para(
        "Les sessions sont désormais <b>composées</b> au lieu d'être rejouées."))
    s.extend(data_table([
        ["Composition", "Contenu"],
        ["<font face='Courier' size='8'>sampled</font> (bénin)",
         "longueur variable (4–14) et répétition des commandes"],
        ["<font face='Courier' size='8'>full</font>",
         "le scénario seul — le cas bruyant, conservé pour le gradient d'intensité"],
        ["<font face='Courier' size='8'>diluted</font>",
         "le scénario entier, avec du bénin intercalé entre ses commandes ; "
         "l'ordre relatif est préservé, donc les paires créer-puis-supprimer "
         "nettoient toujours"],
        ["<font face='Courier' size='8'>minimal</font>",
         "1 à 2 commandes d'attaque en lecture seule enfouies dans une session "
         "bénigne"],
    ], widths=[CONTENT_W * 0.22, CONTENT_W * 0.78]))
    s.append(para(
        "<b>Sûreté :</b> le mode <i>minimal</i> ne pioche que dans une liste en "
        "lecture seule par construction — aucune commande n'y crée d'état, donc "
        "une session interrompue avant son nettoyage ne peut rien laisser derrière "
        "elle. Les scénarios qui créent de l'état ne sont jamais fragmentés."))
    s.append(para("Effet mesuré sur télémétrie réelle :", "h2"))
    s.extend(data_table([
        ["", "Avant", "Après"],
        ["Écart bénin/attaque en longueur de commande", "25,5 car.", "1,9 car."],
        ["unique_command_ratio (bénin réel)", "1,00", "0,77"],
        ["Features admises par la porte de domaine", "3 / 5", "5 / 5"],
    ], widths=[CONTENT_W * 0.52, CONTENT_W * 0.24, CONTENT_W * 0.24],
        align_right=[1, 2]))
    s.extend(figure("fig3_domain_gate",
                    "Figure 1 — Statistique KS par feature, avant et après le "
                    "correctif. Au-delà du seuil, la feature décrit deux "
                    "populations différentes et ne peut pas porter un verdict "
                    "inter-domaines."))

    # ------------------------------------------------------------------ étape 5
    s.append(para("Étape 5 — Un incident de sûreté, et sa correction", "h1"))
    s.extend(callout(
        "Une session collectée a exécuté « mv /usr/local/bin/* /opt/bin/ » en root",
        "Aucun dégât — uniquement parce que <font face='Courier' size='8.5'>"
        "/usr/local/bin</font> était vide. Rien ne l'avait empêché. Deux causes "
        "cumulées : le corpus de commandes bénignes avait été filtré contre les "
        "règles de détection mais <b>jamais contre la destructivité</b>, et le "
        "chemin d'accès à ce corpus était périmé depuis une restructuration du "
        "dépôt — il n'avait donc jamais été réellement chargé. Le défaut s'est "
        "révélé au moment où le chemin a été corrigé.", accent=colors.HexColor("#d03b3b")))
    s.append(para(
        "Un module <font face='Courier' size='8.5'>command_safety.py</font> devient "
        "la <b>définition unique</b>, importée par les deux côtés pour deux raisons "
        "différentes qui exigent la même règle :"))
    s.extend(bullets([
        "<b>Le collecteur — sûreté.</b> Le remplissage bénin s'exécute vraiment, "
        "en root, sur un hôte partagé.",
        "<b>Le générateur — parité.</b> Rien n'y est exécuté, donc rien n'y est "
        "dangereux. Mais si le générateur peut produire une commande que le "
        "collecteur ne peut plus produire, les deux vocabulaires divergent — et "
        "cette divergence réapparaît comme un marqueur de domaine.",
    ]))
    s.append(Spacer(1, 6))
    s.append(para(
        "Deux classes sont bloquées : la <b>mutation d'état</b> et la "
        "<b>non-terminaison</b> (<font face='Courier' size='8.5'>free -s 1</font>, "
        "<font face='Courier' size='8.5'>tail -f</font>, "
        "<font face='Courier' size='8.5'>ping</font> sans "
        "<font face='Courier' size='8.5'>-c</font>). Cette seconde classe est la "
        "plus sournoise : elle bloquerait la session jusqu'au délai d'expiration et "
        "<b>tronquerait silencieusement</b> la collecte au lieu de planter. "
        "1669 commandes rejetées sur environ 3200."))

    # ------------------------------------------------------------------ étape 6
    s.append(para("Étape 6 — Re-collecte et recalibration", "h1"))
    s.append(para(
        "172 sessions réelles collectées en deux lots, sans échec. Puis une "
        "recalibration complète du côté généré : le bénin réel ayant changé, la "
        "calibration du générateur était devenue périmée — et cet écart serait "
        "réapparu comme un marqueur de domaine."))
    s.extend(data_table([
        ["Jeu d'évaluation", "Avant", "Après"],
        ["Sessions réelles labellisées", "79", "256"],
        ["Attaques", "45", "49"],
        ["Taux de base (part d'attaques)", "57,0 %", "19,1 %"],
    ], widths=[CONTENT_W * 0.5, CONTENT_W * 0.25, CONTENT_W * 0.25],
        align_right=[1, 2]))
    s.extend(callout(
        "Un piège évité de justesse",
        "La porte de domaine compare <b>bénin contre bénin uniquement</b> : elle "
        "est structurellement aveugle à une contamination de la classe "
        "<b>attaque</b>. Après avoir corrigé le côté bénin, 45 des 58 attaques du "
        "jeu d'évaluation dataient encore d'avant le correctif — les chiffres "
        "portaient donc sur une classe attaque artefactuelle à 78 %. D'où l'option "
        "<font face='Courier' size='8.5'>--composed-only</font>, qui ne conserve "
        "que les sessions postérieures au correctif.", accent=BLUE))

    # ------------------------------------------------------------------ étape 7
    s.append(para("Étape 7 — Résultat sur base propre", "h1"))
    s.extend(data_table([
        ["Modèle", "ROC-AUC", "P@25", "P@50", "Gain @50"],
        ["<b>PCA</b>", "0,778", "<b>0,72</b>", "<b>0,60</b>", "×3,13"],
        ["ECOD", "0,755", "0,56", "0,54", "×2,82"],
        ["Isolation Forest", "0,775", "0,60", "0,52", "×2,72"],
        ["HBOS", "0,749", "0,44", "0,48", "×2,51"],
        ["MAD (baseline)", "<b>0,798</b>", "0,68", "0,48", "×2,51"],
        ["COPOD", "0,719", "0,36", "0,42", "×2,19"],
    ], widths=[CONTENT_W * 0.30] + [CONTENT_W * 0.175] * 4,
        align_right=[1, 2, 3, 4]))
    s.append(para(
        "Un classeur aléatoire obtient 0,191 à tout <i>k</i>. À k = 50 : "
        "30 attaques trouvées sur 49, pour 20 faux positifs sur 207 sessions "
        "bénignes."))
    s.extend(figure("fig1_precision_at_k",
                    "Figure 2 — Precision@k. Les deux courbes se croisent : le "
                    "baseline est meilleur à petit k, PCA à k moyen."))
    s.extend(callout(
        "Deux points à défendre",
        "<b>1.</b> Le baseline MAD gagne le ROC-AUC et perd le precision@k. Les "
        "deux métriques se contredisent sur les mêmes données — c'est une "
        "justification <i>empirique</i> du choix de precision@k, pas un argument "
        "emprunté à la littérature. Choisir le ROC-AUC aurait fait déployer le "
        "mauvais modèle.<br/><br/>"
        "<b>2.</b> Avant le correctif de collecte, HBOS menait à 0,862. Cet "
        "avantage était l'artefact, pas de l'apprentissage. Le chiffre a baissé "
        "<i>parce que l'évaluation est devenue honnête</i>.", accent=BLUE))

    # ------------------------------------------------------------------ étape 8
    s.append(para("Étape 8 — Le résultat structurant", "h1"))
    s.append(para(
        "Décomposer le rappel par furtivité d'attaque est ce qui transforme "
        "« le modèle marche à 61 % » en une information exploitable."))
    s.extend(figure("fig2_recall_by_composition",
                    "Figure 3 — Rappel par composition d'attaque, avec intervalles "
                    "de confiance de Wilson à 95 %."))
    s.append(para(
        "Les sessions <i>minimal</i> font 19,3 caractères de moyenne contre 19,1 "
        "pour le bénin : sur <b>toutes</b> les features de forme de commande "
        "disponibles, elles sont indistinguables. Le détecteur attrape le cas "
        "bruyant et rate le cas réaliste — or c'est le cas réaliste qui compte, "
        "puisqu'un véritable acteur interne ne lance pas un scénario d'attaque "
        "complet, il glisse deux commandes dans sa journée de travail."))
    s.append(para(
        "Ce n'est pas un échec de réglage mais une <b>limite mesurée</b>, et elle "
        "motive directement les features contextuelles (heure, IP source, cibles "
        "distinctes sur 24 h) — que le laboratoire ne peut pas fournir côté réel "
        "avec une seule identité, une seule IP source et une seule cible."))
    s.extend(figure("fig4_score_distribution",
                    "Figure 4 — Chaque session, par classe. Le recouvrement est le "
                    "résultat : le modèle ne sépare pas proprement, il biaise le "
                    "classement."))

    # ------------------------------------------------------------------ étape 9
    s.append(para("Étape 9 — Figures et documentation", "h1"))
    s.append(para(
        "Cinq figures dans <font face='Courier' size='8.5'>visualisation/</font>, "
        "en PNG et PDF. Le script <b>relit les artefacts produits par "
        "l'entraînement</b> au lieu de recalculer : les figures ne peuvent pas "
        "diverger des chiffres du rapport. Le journal de décisions et le guide du "
        "projet ont été mis à jour en parallèle."))

    # ------------------------------------------------------------------- suite
    s.append(para("Ce qui reste à faire", "h1"))
    s.extend(data_table([
        ["Priorité", "Chantier", "Ce que cela débloque"],
        ["1", "<font face='Courier' size='8'>rule_baseline.py</font> — Pool A/B, "
              "matrice 2×2, test de McNemar",
              "<b>La thèse elle-même.</b> Sans lui, il y a un modèle ML sans point "
              "de comparaison, et « les règles ne suffisent pas » n'est pas démontré."],
        ["2", "Davantage de sessions <i>minimal</i>",
              "Resserre l'intervalle de confiance du 0,27 : temps machine, pas "
              "temps de développement."],
        ["3", "Chronologies par utilisateur dans le générateur",
              "Toutes les features à fenêtre 24 h, aujourd'hui vides de sens."],
        ["4", "Features contextuelles",
              "Le seul levier crédible sur le cas <i>minimal</i>."],
    ], widths=[CONTENT_W * 0.09, CONTENT_W * 0.35, CONTENT_W * 0.56]))
    s.append(para(
        "<b>Ce qu'il ne faut pas faire :</b> ajouter d'autres détecteurs — le "
        "meilleur ne bat qu'à peine un z-score, donc le levier est dans les "
        "features, pas dans les algorithmes ; et régler des seuils pour améliorer "
        "les chiffres, « le ML réglé a battu les règles non réglées » étant la "
        "critique la plus facile à formuler en soutenance."))

    return s


def main() -> int:
    doc = BaseDocTemplate(OUT, pagesize=A4,
                          leftMargin=MARGIN, rightMargin=MARGIN,
                          topMargin=MARGIN, bottomMargin=MARGIN,
                          title="Étapes réalisées — piste non supervisée",
                          author="Projet PAM / détection d'anomalies")
    frame = Frame(MARGIN, MARGIN, CONTENT_W, PAGE_H - 2 * MARGIN, id="body")
    doc.addPageTemplates([PageTemplate(id="std", frames=[frame],
                                       onPage=header_footer)])
    doc.build(build_story())
    print(f"[pdf] -> {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
