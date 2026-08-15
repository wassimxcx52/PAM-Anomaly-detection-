from pathlib import Path

import pandas as pd
import numpy as np

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)


# Repo root, so the script works from any working directory.
OUT_DIR = Path(__file__).resolve().parents[2] / "feature_extraction" / "out"

# Percentile of the BENIGN training distances above which a session is an
# anomaly. Fitted on train only, then applied unchanged to the eval set.
THRESHOLD_PCT = 99

# SOC alert budgets for precision@k (see decision: precision@k, not ROC-AUC).
K_BUDGETS = [10, 20, 50]


# ============================================================
# 1. LOAD DATASET
# ============================================================

df = pd.read_csv(OUT_DIR / "features_benign.csv")

print("Dataset loaded")
print("Dataset shape:", df.shape)


# ============================================================
# 2. FEATURES USED BY K-MEANS
# ============================================================

features = [
    "duration_sec_feat",
    "start_hour",
    "off_hours_flag",
    "is_weekend",

    "command_count",
    "unique_command_ratio",
    "avg_command_length",
    "command_entropy",

    "new_source_ip_for_user",
    "new_source_ip_globally",
    "ip_foreign_to_user",

    "distinct_source_ips_prior",
    "distinct_source_ips_24h",
    "source_ip_entropy"
]


X = df[features]


# ============================================================
# 3. STANDARDIZATION
# ============================================================

scaler = StandardScaler()

X_scaled = scaler.fit_transform(X)


# ============================================================
# 4. K-MEANS MODEL
# ============================================================

kmeans = KMeans(
    n_clusters=2,
    random_state=42,
    n_init=10
)

df["cluster"] = kmeans.fit_predict(X_scaled)


# ============================================================
# 5. DISTANCE TO THE CLOSEST CENTROID
# ============================================================

distances = kmeans.transform(X_scaled)

df["distance_to_centroid"] = np.min(
    distances,
    axis=1
)


# ============================================================
# 6. DEFINE ANOMALY THRESHOLD
# ============================================================

threshold = np.percentile(
    df["distance_to_centroid"],
    THRESHOLD_PCT
)

print("\nAnomaly threshold:", threshold)


# ============================================================
# 7. DETECT ANOMALIES
# ============================================================

df["kmeans_anomaly"] = (
    df["distance_to_centroid"] > threshold
).astype(int)


# ============================================================
# 8. DISPLAY RESULTS IN TERMINAL
# ============================================================

print("\n==============================")
print("K-MEANS RESULTS")
print("==============================")

print(
    "Normal sessions:",
    (df["kmeans_anomaly"] == 0).sum()
)

print(
    "Anomalies:",
    (df["kmeans_anomaly"] == 1).sum()
)


print("\nCluster distribution:")

print(
    df["cluster"]
    .value_counts()
    .sort_index()
)


# ============================================================
# 9. SAVE COMPLETE RESULTS AS CSV
# ============================================================

df.to_csv(
    OUT_DIR / "features_benign_kmeans.csv",
    index=False
)


# ============================================================
# 10. SAVE RESULTS AS JSON FOR WAZUH
# ============================================================

df.to_json(
    OUT_DIR / "features_benign_kmeans.json",
    orient="records",
    lines=True
)


# ============================================================
# 11. SAVE ONLY ANOMALIES FOR WAZUH
# ============================================================

anomalies = df[
    df["kmeans_anomaly"] == 1
]

anomalies.to_json(
    OUT_DIR / "kmeans_anomalies.json",
    orient="records",
    lines=True
)


print("\nFiles generated:")

print(
    "feature_extraction/out/"
    "features_benign_kmeans.csv"
)

print(
    "feature_extraction/out/"
    "features_benign_kmeans.json"
)

print(
    "feature_extraction/out/"
    "kmeans_anomalies.json"
)


# ============================================================
# 12. SCORE THE LABELLED EVALUATION SET
# ============================================================
#
# features_benign.csv is benign-only, so no confusion matrix can be
# computed on it. Metrics are measured on the isolated REAL eval set,
# which was never trained on. The scaler, the centroids and the
# threshold all come from the benign training fit above.

eval_df = pd.read_csv(OUT_DIR / "features_eval_real.csv")

print("\n\n==============================")
print("EVALUATION ON REAL SESSIONS")
print("==============================")

print("Eval shape:", eval_df.shape)

X_eval_scaled = scaler.transform(eval_df[features])

eval_df["cluster"] = kmeans.predict(X_eval_scaled)

eval_df["distance_to_centroid"] = np.min(
    kmeans.transform(X_eval_scaled),
    axis=1
)

eval_df["kmeans_anomaly"] = (
    eval_df["distance_to_centroid"] > threshold
).astype(int)


# Ground truth: 1 = attack, 0 = benign.
y_true = (eval_df["label"] == "attack").astype(int)
y_pred = eval_df["kmeans_anomaly"]
y_score = eval_df["distance_to_centroid"]

print("\nGround truth:", int(y_true.sum()), "attack /",
      int((1 - y_true).sum()), "benign")
print("Flagged by K-Means:", int(y_pred.sum()))


# ============================================================
# 13. CONFUSION MATRIX
# ============================================================

cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

tn, fp, fn, tp = cm.ravel()

print("\n--- CONFUSION MATRIX ---")
print("                 pred benign   pred attack")
print(f"true benign      {tn:>11}   {fp:>11}")
print(f"true attack      {fn:>11}   {tp:>11}")

print(f"\nTN={tn}  FP={fp}  FN={fn}  TP={tp}")


# ============================================================
# 14. CLASSIFICATION METRICS
# ============================================================

print("\n--- METRICS (threshold = "
      f"p{THRESHOLD_PCT} of train distances) ---")

print(f"Accuracy          : {accuracy_score(y_true, y_pred):.4f}")
print("Balanced accuracy : "
      f"{balanced_accuracy_score(y_true, y_pred):.4f}")
print("Precision (attack): "
      f"{precision_score(y_true, y_pred, zero_division=0):.4f}")
print("Recall    (attack): "
      f"{recall_score(y_true, y_pred, zero_division=0):.4f}")
print("F1        (attack): "
      f"{f1_score(y_true, y_pred, zero_division=0):.4f}")

print("\n--- THRESHOLD-FREE (ranking quality) ---")
print(f"ROC-AUC           : {roc_auc_score(y_true, y_score):.4f}")
print("PR-AUC (avg prec) : "
      f"{average_precision_score(y_true, y_score):.4f}")

print("\n--- CLASSIFICATION REPORT ---")
print(classification_report(
    y_true,
    y_pred,
    target_names=["benign", "attack"],
    zero_division=0
))


# ============================================================
# 15. PRECISION@K  (the SOC-budget metric)
# ============================================================
#
# Rank every eval session by distance to its centroid, take the top k
# as the analyst's alert queue, and measure how many are real attacks.

ranked = y_true.iloc[
    np.argsort(-y_score.to_numpy(), kind="stable")
]

n_attacks = int(y_true.sum())

print("--- PRECISION@K ---")
print("   k   hits   precision@k   recall@k")

for k in K_BUDGETS:
    if k > len(ranked):
        continue

    hits = int(ranked.iloc[:k].sum())

    print(f"{k:>4}   {hits:>4}   {hits / k:>11.4f}   "
          f"{hits / n_attacks:>8.4f}")


# ============================================================
# 16. SAVE SCORED EVALUATION SET
# ============================================================

eval_df.to_csv(
    OUT_DIR / "features_eval_real_kmeans.csv",
    index=False
)

eval_df.to_json(
    OUT_DIR / "features_eval_real_kmeans.json",
    orient="records",
    lines=True
)

print("\nFiles generated:")

print(
    "feature_extraction/out/"
    "features_eval_real_kmeans.csv"
)

print(
    "feature_extraction/out/"
    "features_eval_real_kmeans.json"
)