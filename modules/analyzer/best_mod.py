import pandas as pd
import numpy as np
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder
from sklearn.impute import SimpleImputer
from xgboost import XGBRegressor
from sklearn.metrics import mean_absolute_error

# ---------- Utilitaires ----------
def normalize_series(s):
    return s.astype(str).str.strip().str.lower().replace({'nan':'unknown'})

class RareCategoryGrouper(BaseEstimator, TransformerMixin):
    """
    Transforme les catégories rares en 'other'.
    - fit : calcule les catégories fréquentes (>= threshold)
    - transform : remplace les valeurs non fréquentes par 'other'
    """
    def __init__(self, threshold=0.01):
        self.threshold = threshold
        self.frequent_ = {}  # col -> set(values)

    def fit(self, X, y=None):
        # X est DataFrame
        for col in X.columns:
            vc = X[col].value_counts(normalize=True)
            self.frequent_[col] = set(vc[vc >= self.threshold].index)
        return self

    def transform(self, X):
        Xt = X.copy()
        for col in Xt.columns:
            freq = self.frequent_.get(col, set())
            Xt.loc[:, col] = Xt[col].apply(lambda v: v if v in freq else 'other')
        return Xt

# ---------- Chargement ----------
vuln_file_path = '/home/sam/pen_ia/modules/analyzer/data/CVSS v3.1.csv'
vuln_data = pd.read_csv(vuln_file_path)

vuln_data_features = [
    'attack_vector','attack_complexity','privileges_required','user_interaction',
    'scope','confidentiality_impact','integrity_impact','availability_impact'
]
X_full = vuln_data[vuln_data_features].copy()
y_full = vuln_data['base_score'].copy()

# normalize on full dataset BEFORE split? No: we will normalize inside pipeline where fit sees train only.
# But for simplicity here we show a train-test example:
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X_full, y_full, test_size=0.2, random_state=42)

# Normalize text columns (do it on both but real pipeline would include this step)
for df in (X_train, X_test):
    for c in X_train.columns:
        df.loc[:, c] = normalize_series(df[c])

# ---------- Pipeline ----------
# Grouper catégories rares (fit sur train puis transform test)
grouper = RareCategoryGrouper(threshold=0.01)
grouper.fit(X_train)
X_train_grp = grouper.transform(X_train)
X_test_grp = grouper.transform(X_test)

# Preprocessor: imputer (au cas où) + OneHotEncoder
categorical_cols = list(X_train_grp.columns)
numerical_cols = []  # none here

categorical_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='most_frequent')),
    ('onehot', OneHotEncoder(handle_unknown='ignore', sparse_output=False))
])

preprocessor = ColumnTransformer(transformers=[
    ('cat', categorical_transformer, categorical_cols)
], remainder='drop')

model = XGBRegressor(n_estimators=300, learning_rate=0.05, n_jobs=4, random_state=42)

pipe = Pipeline(steps=[('preproc', preprocessor), ('model', model)])

# Fit et predict
pipe.fit(X_train_grp, y_train)
preds = pipe.predict(X_test_grp)
print("MAE test:", mean_absolute_error(y_test, preds))

# Prédictions sur ton jeu externe `predicti` (appliquer normalization + grouper puis predict)
# Exemple pour ta variable predicti (définie précédemment)
# predicti_norm = predicti.copy()
# for c in predicti_norm.columns:
#     predicti_norm.loc[:, c] = normalize_series(predicti_norm[c])
# predicti_grp = grouper.transform(predicti_norm)
# preds_external = pipe.predict(predicti_grp)
# print("Preds external:", preds_external)
