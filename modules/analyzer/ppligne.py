import pandas as pd 
from sklearn.preprocessing import OrdinalEncoder
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.model_selection import cross_val_score
from xgboost import XGBRegressor







# save filepath to variable for easier access
vuln_file_path = '/home/sam/pen_ia/modules/analyzer/data/CVSS v3.1.csv'
# read the data and store data in DataFrame titled vuln_data
vuln_data = pd.read_csv(vuln_file_path) 
# print a summary of the data in vuln data
print(vuln_data.info())
print(vuln_data.head())
print(vuln_data.describe())

y=vuln_data['base_score']
vuln_data_features=['attack_vector','attack_complexity','privileges_required','user_interaction','scope','confidentiality_impact','integrity_impact','availability_impact']
X=vuln_data[vuln_data_features]
print(X.head(5))


# "Cardinality" means the number of unique values in a column
# Select categorical columns with relatively low cardinality (convenient but arbitrary)
categorical_cols = [cname for cname in X.columns if X[cname].nunique() < 10 and 
                        X[cname].dtype == "object"]

# Select numerical columns
numerical_cols = [cname for cname in X.columns if X[cname].dtype in ['int64', 'float64']]

# Keep selected columns only
my_cols = categorical_cols + numerical_cols
X = X[my_cols].copy()



# Preprocessing for numerical data
numerical_transformer = SimpleImputer(strategy='constant')

# Preprocessing for categorical data
categorical_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='most_frequent')),
    ('onehot', OneHotEncoder(handle_unknown='ignore'))
])

# Bundle preprocessing for numerical and categorical data
preprocessor = ColumnTransformer(
    transformers=[
        ('num', numerical_transformer, numerical_cols),
        ('cat', categorical_transformer, categorical_cols)
    ])

model = RandomForestRegressor(n_estimators=100, random_state=0)

# Bundle preprocessing and modeling code in a pipeline
my_pipeline = Pipeline(steps=[('preprocessor', preprocessor),
                              ('regressor', XGBRegressor(n_estimators=1000, learning_rate=0.05, n_jobs=4))
                             ])

# Multiply by -1 since sklearn calculates *negative* MAE
scores = -1 * cross_val_score(my_pipeline, X, y,
                              cv=5,
                              scoring='neg_mean_absolute_error')

print("MAE scores:\n", scores)
print("Average MAE score (across experiments):")
print(scores.mean())


data = {
    'attack_vector': ['Network', 'Local', 'ADJACENT','Local', 'Network'],
    'attack_complexity': ['Low', 'High', 'Low', 'High', 'Low'],
    'privileges_required': ['None', 'Low', 'High', 'Low', 'None'],
    'user_interaction': ['None', 'Required', 'None', 'Required', 'None'],
    'scope': ['Changed', 'Unchanged', 'Unchanged', 'Changed', 'Changed'],
    'confidentiality_impact': ['High', 'Low', 'Low', 'High', 'None'],
    'integrity_impact': ['High', 'up', 'None', 'Low', 'None'],
    'availability_impact': ['High', 'Low', 'Low', 'High', 'None'],
    'base_score': [9.8, 6.5, 4.3, 7.2, 5.0]  # variable cible
}
test=pd.DataFrame(data)
cvss=test['base_score']
predicti=test[vuln_data_features]

def normalize_df(df, cols):
    for c in cols:
        df[c] = df[c].astype(str).str.strip().str.lower().replace({'nan':'unknown'})
    return df

# appliquer sur train et test
X = normalize_df(X, X.columns)
predicti = normalize_df(predicti, predicti.columns)

# option: regrouper catégories rares dans le train
for c in X.columns:
    counts = X[c].value_counts(normalize=True)
    rare = counts[counts < 0.01].index  # seuil 1%
    X[c] = X[c].replace(list(rare), 'other')
    predicti[c] = predicti[c].replace(list(rare), 'other')  # appliquer même regroupement


# ====== Entraînement final sur tout le dataset ======
my_pipeline.fit(X, y)

# ====== Prédictions sur les nouvelles vulnérabilités ======
predictions = my_pipeline.predict(predicti)

print("\nScores réels :")
print(cvss.values)

print("\nScores prédits :")
print(predictions)

# ====== Évaluation finale ======
mae_final = mean_absolute_error(cvss, predictions)
print(f"\n✅ MAE sur le jeu de test externe : {mae_final:.4f}")



