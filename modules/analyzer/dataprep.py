import pandas as pd

# Charger le CSV
df = pd.read_csv("/home/sam/pen_ia/modules/analyzer/data/detailed.csv")

print(df.describe())