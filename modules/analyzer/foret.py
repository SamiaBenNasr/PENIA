import pandas as pd 
from sklearn.tree import DecisionTreeRegressor
from sklearn.preprocessing import OrdinalEncoder
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestRegressor






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


# Apply ordinal encoder to each column with categorical data
ordinal_encoder = OrdinalEncoder()

label_X_train = train_X.copy()
label_X_valid = val_X.copy()

label_X_train[object_cols] = ordinal_encoder.fit_transform(train_X[object_cols])
label_X_valid[object_cols] = ordinal_encoder.transform(val_X[object_cols])



vuln_model= RandomForestRegressor(random_state=1)
vuln_model.fit(label_X_train, train_y)
print("Making predictions for the following 5 vuln:")
print(val_X.head())
print("The predictions are")
predicted_scores=vuln_model.predict(label_X_valid)
print(predicted_scores)
print("The MAE for this model is")
print(mean_absolute_error(val_y, predicted_scores))

