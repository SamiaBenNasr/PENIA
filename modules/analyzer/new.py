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
import joblib







# save filepath to variable for easier access
vuln_file_path = '/home/sam/pen_ia/modules/analyzer/data/train.csv'
# read the data and store data in DataFrame titled vuln_data
vuln_data = pd.read_csv(vuln_file_path) 
# Supprimer les lignes sans exploit_cvss
vuln_data = vuln_data.dropna(subset=['exploit_cvss'])

# Supprimer les colonnes totalement vides
vuln_data = vuln_data.dropna(axis=1, how='all')


y=vuln_data['cvss_score_moyen']
vuln_data_features=['port', 'protocol', 'service', 'product', 'version','cpe','exploit_type','is_exploit','cve_list','ref_links','exploit_id']
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
numerical_transformer = SimpleImputer(strategy='mean', keep_empty_features=True)

# Preprocessing for categorical data
categorical_transformer = Pipeline(steps=[
    ('imputer', SimpleImputer(strategy='constant', fill_value='unknown', keep_empty_features=True)),
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


my_pipeline.fit(X, y)


# Sauvegarder le modèle entraîné
joblib.dump(my_pipeline, "/home/sam/pen_ia/modules/analyzer/models/cvss_predictor.pkl")

print("✅ Modèle sauvegardé sous cvss_predictor.pkl")