import pandas as pd

# Charger le CSV
df = pd.read_csv("/home/sam/pen_ia/modules/analyzer/data/nmap_vuln_detailed.csv")

# 1. Calculer la moyenne CVSS
def moyenne_cvss(cvss_str):
    if pd.isna(cvss_str) or cvss_str.strip() == "":
        return None
    # On convertit chaque valeur en float
    try:
        cvss_values = [float(x.strip()) for x in cvss_str.split(",")]
        return sum(cvss_values) / len(cvss_values)
    except:
        return None

df["cvss_score_moyen"] = df["cvss_list"].apply(moyenne_cvss)

# 2. Transformer is_exploit en booléen
df["is_exploit"] = df["is_exploit"].astype(bool)

# Sauvegarder le nouveau CSV
df.to_csv("/home/sam/pen_ia/modules/analyzer/data/test.csv", index=False)
