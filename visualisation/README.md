# visualisation/

Figures de la piste non supervisée. Régénérer avec :

```powershell
python visualisation/plot_unsupervised.py
```

Le script **relit les artefacts que `ml/unsupervised/train.py` a écrits** — il ne
recalcule rien. Les figures ne peuvent donc pas diverger des chiffres du rapport :
si le bake-off est relancé, il suffit de relancer ce script.

Chaque figure sort en **PNG** (300 dpi, pour les diapositives) et en **PDF**
(vectoriel, pour `\includegraphics` dans le rapport LaTeX).

| Figure | Ce qu'elle montre | Forme choisie |
|---|---|---|
| `fig1_precision_at_k` | Les 6 détecteurs sur tout le budget d'alertes, avec la ligne du classeur aléatoire | **Emphase** — PCA et le baseline MAD en couleur, les 4 autres en gris. Le sujet est « le meilleur détecteur appris contre le baseline obligatoire » ; six couleurs égales l'enterreraient. |
| `fig2_recall_by_composition` | **La figure centrale.** Rappel par furtivité d'attaque, avec IC 95 % de Wilson | Barres, une seule teinte ordonnée foncé→clair à mesure que l'attaque devient furtive : la rampe et le récit pointent dans le même sens. |
| `fig3_domain_gate` | Statistique KS par feature, avant et après le correctif de collecte | **Dumbbell** — c'est un avant/après par élément. Une teinte, deux nuances. |
| `fig4_score_distribution` | Chaque session, score PCA, par classe, avec le seuil top-50 | Strip plot : n=256 est assez petit pour montrer **chaque** session, et le recouvrement est précisément le résultat. Seule figure où les deux classes sont le sujet, donc seule paire catégorielle. |
| `fig5_recall_by_tactic` | Rappel par tactique MITRE | Barres, teinte séquentielle. |

## Notes de lecture

- **Fig. 1** — les deux courbes se croisent : MAD est meilleur à petit *k*, PCA à
  *k* moyen. C'est l'argument empirique pour `precision@k` plutôt que ROC-AUC
  (où MAD gagne). Ne pas « lisser » ce croisement.
- **Fig. 3** — `command_count` **monte** (0.041 → 0.131). C'est honnête et attendu :
  le correctif a changé la distribution du bénin réel, donc l'accord parfait de
  départ s'est légèrement dégradé. Il reste très en dessous du seuil.
- **Fig. 3** — la colonne « avant » est une constante codée en dur dans le script :
  cette exécution de la porte est antérieure à l'artefact CSV. Documenté sur place.

## Choix assumés

Toutes les figures sont en **mode clair uniquement** : ce sont des figures
d'impression pour un rapport, pas une page web thématisable.

La palette est celle validée par `validate_palette.js` (bleu `#2a78d6` / orange
`#eb6834` : ΔE CVD 24.7, normal 33.6, contraste ≥ 3:1 sur la surface claire).
