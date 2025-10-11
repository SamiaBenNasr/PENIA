# streamlit_app.py
import streamlit as st
import pandas as pd
from pathlib import Path
import importlib
import joblib
from sklearn.metrics import mean_absolute_error

# <-- adapte ces imports selon l'emplacement réel de tes fonctions de scan -->
from modules.scan.nmap import run_nmap_scan
from modules.scan.nikto import run_nikto_scan

# Chemin possible du module/pkl
MODEL_MODULE_PATH = "modules.analyzer.new"   # doit exposer `my_pipeline` et `vuln_data_features` idéalement
MODEL_PKL_PATH = "/home/sam/pen_ia/modules/analyzer/models/cvss_predictor.pkl"

st.set_page_config(page_title="Pen IA - Priorisation", layout="wide")
st.title("Pen IA — Priorisation des vulnérabilités (prédiction CVSS)")
st.markdown("Ce module applique un modèle de machine learning aux résultats de ton scan pour **prédire un score CVSS moyen** par vulnérabilité. Le modèle utilise directement les résultats du scan pour faire ses prédictions.")
st.markdown("---")

# ---------- Charger le modèle ----------
def load_pipeline():
    # 1) tenter d'importer depuis le module python (new.py)
    try:
        mod = importlib.import_module(MODEL_MODULE_PATH)
        if hasattr(mod, "my_pipeline"):
            st.success("Modèle chargé depuis le module Python.")
            # si le module expose la liste des features, l'utiliser
            vuln_features = getattr(mod, "vuln_data_features", None)
            return getattr(mod, "my_pipeline"), vuln_features
    except Exception as e:
        # ne pas échouer tout de suite, on tente fallback
        st.info("Impossible d'importer my_pipeline depuis le module Python (fallback vers .pkl si présent).")

    # 2) fallback : charger un .pkl si présent
    p = Path(MODEL_PKL_PATH)
    if p.exists():
        try:
            pipeline = joblib.load(str(p))
            st.success(f"Modèle chargé depuis {MODEL_PKL_PATH}")
            return pipeline, None
        except Exception as e:
            st.error(f"Échec du chargement du modèle .pkl : {e}")
            return None, None

    st.warning("Aucun modèle trouvé. Assure-toi que `modules/analyzer/new.py` exporte `my_pipeline` ou crée un fichier .pkl.")
    return None, None

my_pipeline, vuln_features_from_module = load_pipeline()

# Si le module n'expose pas les features, on les définit (doit correspondre à ton entraînement)
if vuln_features_from_module is None:
    VULN_FEATURES = [
        'port', 'protocol', 'service', 'product', 'version',
        'cpe', 'exploit_type', 'is_exploit', 'cve_list', 'ref_links', 'exploit_id'
    ]
else:
    VULN_FEATURES = vuln_features_from_module



# Instructions pour l'utilisateur : comment produire le CSV utilisé par le modèle
st.sidebar.header("Procédure recommandée (Nmap → CSV)")
st.sidebar.markdown(
    "1. Lancez un scan nmap et convertissez le XML en CSV.\n\n"
    "2. Téléchargez le CSV converti (bouton dans l'interface).\n\n"
    "3. Revenez ici et chargez le CSV. Le modèle utilisera ce CSV pour faire les prédictions."
)
st.sidebar.markdown("---")
uploaded_file = st.sidebar.file_uploader("Charger le CSV converti depuis Nmap ", type=["csv"])


st.sidebar.markdown("---")
st.sidebar.write("Colonnes utilisées par le modèle :")
st.sidebar.write(VULN_FEATURES)

# ---------- Action : lancer / charger et prédire ----------
if st.button("Lancer / Charger et prédire"):
    # 1) récupérer les données
    df = None
    try:
        if uploaded_file is None:
                st.error("Aucun fichier CSV chargé.")
                st.stop()
        df = pd.read_csv(uploaded_file)

    except Exception as e:
        st.exception(f"Erreur lors de l'exécution du scan / lecture du CSV : {e}")
        st.stop()

    if not isinstance(df, pd.DataFrame):
        st.error("Les fonctions de scan doivent renvoyer un pandas.DataFrame. Adapte run_nmap_scan / run_nikto_scan.")
        st.stop()

    st.success(f"Données chargées : {len(df)} lignes.")
    st.write("Aperçu des résultats bruts :")
    st.dataframe(df.head(10))

    # 2) informer l'utilisateur que le modèle utilisera ces données
    st.info("ℹ️ Le modèle va utiliser ces résultats de scan pour prédire le score CVSS moyen de chaque entrée. Les prédictions servent à prioriser les vulnérabilités — elles n'éliminent pas l'analyse humaine.")

    # 3) préparer les colonnes attendues
    missing_cols = [c for c in VULN_FEATURES if c not in df.columns]
    if missing_cols:
        st.warning(f"Colonnes manquantes détectées (elles seront ajoutées avec valeur NaN par défaut) : {missing_cols}")
        for c in missing_cols:
            df[c] = pd.NA

    # garder uniquement les colonnes dans l'ordre attendu
    X_input = df[VULN_FEATURES].copy()

    # conversions simples
    if 'is_exploit' in X_input.columns:
        try:
            X_input['is_exploit'] = X_input['is_exploit'].astype(float).fillna(0).astype(int)
        except Exception:
            X_input['is_exploit'] = X_input['is_exploit'].map({True:1, False:0}).fillna(0).astype(int)

    # 4) prédiction
    if my_pipeline is None:
        st.error("Aucun pipeline disponible pour effectuer la prédiction. Voir messages plus haut.")
        st.stop()

    try:
        preds = my_pipeline.predict(X_input)
        df['predicted_cvss_score'] = preds
    except Exception as e:
        st.exception(f"Erreur lors de la prédiction : {e}")
        st.stop()

    # 5) affichage des résultats triés
    st.markdown("### Résultats avec scores CVSS prédits")
    df_display = df[['port', 'protocol', 'service', 'product', 'version', 'predicted_cvss_score']].copy()
    df_display = df_display.sort_values(by='predicted_cvss_score', ascending=False).reset_index(drop=True)
    st.dataframe(df_display)

    # 6) extra : statistiques sommaires
    st.markdown("### Synthèse")
    st.metric("Nombre d'entrées", len(df))
    st.metric("Moyenne des scores prédits", f"{df['predicted_cvss_score'].mean():.3f}")
    st.metric("Max score prédit", f"{df['predicted_cvss_score'].max():.3f}")

    # 7) afficher les vulnérabilités critiques (>=7)
    high = df[df['predicted_cvss_score'] >= 7].sort_values('predicted_cvss_score', ascending=False)
    if not high.empty:
        st.warning(f"{len(high)} vulnérabilités hautement critiques détectées (score >= 7).")
        st.dataframe(high[['port','service','product','predicted_cvss_score']].head(50))
    else:
        st.info("Aucune vulnérabilité avec score >= 7 détectée.")
    # afficher les vulnérabilités modérées (4-7)
    moderate = df[(df['predicted_cvss_score'] >= 4) & (df['predicted_cvss_score'] < 7)].sort_values('predicted_cvss_score', ascending=False)
    if not moderate.empty:
        st.info(f"{len(moderate)} vulnérabilités modérées détectées (score entre 4 et 7).")
        st.dataframe(moderate[['port','service','product','predicted_cvss_score']].head(50))
    else:
        st.info("Aucune vulnérabilité avec score entre 4 et 7 détectée.")
    # afficher les vulnérabilités faibles (<4)
    low = df[df['predicted_cvss_score'] < 4].sort_values('predicted_cvss_score', ascending=False)
    if not low.empty:
        st.success(f"{len(low)} vulnérabilités faibles détectées (score < 4).")
        st.dataframe(low[['port','service','product','predicted_cvss_score']].head(50))
    else:
        st.info("Aucune vulnérabilité avec score < 4 détectée.")
    # afficher la distribution des scores
    st.markdown("### Distribution des scores CVSS prédits")
    st.bar_chart(df['predicted_cvss_score'].value_counts().sort_index())
    # afficher l'histogramme des scores
    st.markdown("### Histogramme des scores CVSS prédits")
    st.bar_chart(df['predicted_cvss_score'], width=800, height=400) 
    

    # 8) MAE si la vérité terrain est présente
    if 'cvss_score_moyen' in df.columns:
        mask = df['cvss_score_moyen'].notna()
        if mask.sum() > 0:
            try:
                mae = mean_absolute_error(df.loc[mask, 'cvss_score_moyen'], df.loc[mask, 'predicted_cvss_score'])
                st.success(f"MAE sur lignes avec label réel : {mae:.4f}")
            except Exception as e:
                st.warning(f"Impossible de calculer le MAE : {e}")
        else:
            st.info("La colonne 'cvss_score_moyen' existe mais contient uniquement des NaN. MAE non calculable.")
    else:
        st.info("La colonne 'cvss_score_moyen' n'est pas présente : le MAE ne peut pas être calculé.")

    # 9) sauvegarder / télécharger résultats
    save_path = "/home/sam/pen_ia/modules/analyzer/data/test_with_predictions.csv"
    try:
        df.to_csv(save_path, index=False)
        st.success(f"Résultats sauvegardés localement : {save_path}")
    except Exception as e:
        st.warning(f"Impossible de sauvegarder localement : {e}")
        st.download_button("Télécharger les résultats (CSV)", df.to_csv(index=False).encode('utf-8'), file_name="predictions.csv", mime="text/csv")

    st.info("Fin du traitement. Utilise ces prédictions pour prioriser le travail de remédiation — fais toujours une revue humaine avant toute intervention.")
