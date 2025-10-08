import pandas as pd 
from sklearn.tree import DecisionTreeRegressor
from sklearn.preprocessing import OrdinalEncoder
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor
from xgboost import XGBRegressor
from sklearn.preprocessing import OneHotEncoder






# save filepath to variable for easier access
vuln_file_path = '/home/sam/pen_ia/modules/analyzer/data/CVSS v3.1.csv'
# read the data and store data in DataFrame titled vuln_data
vuln_data = pd.read_csv(vuln_file_path) 
# print a summary of the data in vuln data
print(vuln_data.info())
print(vuln_data.head())
print(vuln_data.describe())

y=vuln_data['base_score']
vuln_data_features=['attack_vector','attack_complexity','privileges_required','user_interaction','scope','confidentiality_impact','integrity_impact','availability_impact','base_severity']
X=vuln_data[vuln_data_features]
print(X.head(5))

train_X, val_X, train_y, val_y = train_test_split(X, y, random_state = 0)


s = (X.dtypes == 'object')
object_cols = list(s[s].index)

# Apply one-hot encoder to each column with categorical data
OH_encoder = OneHotEncoder(handle_unknown='ignore', sparse_output=False)

OH_cols_train = pd.DataFrame(OH_encoder.fit_transform(train_X[object_cols]))
OH_cols_valid = pd.DataFrame(OH_encoder.transform(val_X[object_cols]))




# One-hot encoding removed index; put it back
OH_cols_train.index = train_X.index
OH_cols_valid.index = val_X.index

# Remove categorical columns (will replace with one-hot encoding)
num_X_train = train_X.drop(object_cols, axis=1)
num_X_valid = val_X.drop(object_cols, axis=1)

# Add one-hot encoded columns to numerical features
OH_X_train = pd.concat([num_X_train, OH_cols_train], axis=1)
OH_X_valid = pd.concat([num_X_valid, OH_cols_valid], axis=1)

# Ensure all columns have string type
OH_X_train.columns = OH_X_train.columns.astype(str)
OH_X_valid.columns = OH_X_valid.columns.astype(str)



X_train = OH_X_train
X_valid = OH_X_valid


my_model = XGBRegressor(n_estimators=1000, learning_rate=0.05, n_jobs=4)
my_model.fit(
    X_train, train_y,
    eval_set=[(X_valid, val_y)],
    verbose=False
)



predictions = my_model.predict(X_valid)
print("Mean Absolute Error: " + str(mean_absolute_error(predictions, val_y)))