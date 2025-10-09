import pandas as pd
import numpy as np
from sklearn.model_selection import cross_val_score
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder, FunctionTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from xgboost import XGBRegressor
import re

# ============================
# 🔹 1. Chargement du dataset
# ============================
file_path = '/home/sam/pen_ia/modules/analyzer/data/nmap_vuln_detailed.csv'
df = pd.read_csv(file_path)

print("✅ Dataset chargé :", df.shape)
print(df.columns.tolist())

# ============================
# 🔹 2. Prétraitement / Features
# ============================

# Supprimer les lignes sans score cible

y = df["exploit_cvss"]
# Nettoyer la target
y = y.fillna(y.mean())

# Ajouter des features dérivées
df["n_ref_links"] = df["ref_links"].apply(lambda x: len(str(x).split(",")) if pd.notna(x) else 0)

df["vendor"] = df["cpe"].apply(lambda x: str(x).split(":")[3] if pd.notna(x) and len(str(x).split(":")) > 3 else "")
df["product_name"] = df["cpe"].apply(lambda x: str(x).split(":")[4] if pd.notna(x) and len(str(x).split(":")) > 4 else "")

df["is_exploit"] = df["is_exploit"].astype(int, errors="ignore")

# ============================
# 🔹 3. Sélection des features
# ============================
feature_cols = [
    "port", "protocol", "service", "product", "version", "cpe",
    "vendor", "product_name", "exploit_type", "is_exploit", "n_ref_links",
]

# Filtrer seulement les colonnes existantes
feature_cols = [c for c in feature_cols if c in df.columns]
X = df[feature_cols]

# ============================
# 🔹 4. Pipelines de prétraitement
# ============================
categorical_cols = [c for c in X.columns if X[c].dtype == "object" and c not in ["title", "description"]]
numeric_cols = [c for c in X.columns if X[c].dtype in ["int64", "float64"]]

# Prétraitement numérique
num_transformer = SimpleImputer(strategy="mean")

# Prétraitement catégoriel
cat_transformer = Pipeline(steps=[
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", OneHotEncoder(handle_unknown="ignore"))
])



# Combine tous les preprocessors
preprocessor = ColumnTransformer(transformers=[
    ("num", num_transformer, numeric_cols),
    ("cat", cat_transformer, categorical_cols),
], remainder="drop")

# ============================
# 🔹 5. Modèle XGBoost
# ============================
model = XGBRegressor(
    n_estimators=600,
    learning_rate=0.05,
    max_depth=6,
    subsample=0.8,
    colsample_bytree=0.8,
    random_state=42,
    n_jobs=4
)


# Pipeline final
pipeline = Pipeline(steps=[
    ("preprocessor", preprocessor),
    ("regressor", model)
])

# ============================
# 🔹 6. Évaluation croisée
# ============================
print("\n🔄 Entraînement et validation croisée...")
scores = -1 * cross_val_score(
    pipeline, X, y,
    cv=5,
    scoring="neg_mean_absolute_error"
)

print("\n📊 Résultats Validation Croisée (MAE par fold):")
print(scores)
print(f"\n✅ MAE moyen = {scores.mean():.3f}")

# ============================
# 🔹 7. Importance des features
# ============================
print("\n📈 Entraînement final pour extraire les importances...")
pipeline.fit(X, y)

reg = pipeline.named_steps["regressor"]
importances = reg.feature_importances_

print("\nTop 20 features importantes (XGBoost) :")
try:
    cat_names = pipeline.named_steps["preprocessor"].named_transformers_["cat"].named_steps["onehot"].get_feature_names_out(categorical_cols)
except:
    cat_names = []

feature_names = list(numeric_cols) + list(cat_names)
feature_importances = sorted(zip(feature_names, importances[:len(feature_names)]), key=lambda x: x[1], reverse=True)

for name, score in feature_importances[:20]:
    print(f"{name:30s} {score:.4f}")

print("\n✅ Modèle prêt pour la prédiction de CVSS scores.")
