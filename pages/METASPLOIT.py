#Analyse de vulnérabilités avec Metasploit
import streamlit as st
from modules.vuln.metasploit import exploit_and_console
st.set_page_config(page_title="Pen IA - Exploitation", layout="wide")
st.markdown("## Lancer un exploit avec Metasploit")
st.markdown("Exécutez automatiquement un exploit et interagissez avec la session Meterpreter ou Shell.")
st.markdown("---")


try:
    exploit_and_console()
except ImportError as e:
    st.error(f"Erreur lors de l'importation du module Metasploit: {e}")
    