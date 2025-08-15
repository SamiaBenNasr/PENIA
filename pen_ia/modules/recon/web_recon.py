import requests
from bs4 import BeautifulSoup
import re
import streamlit as st  # ➤ Ajout de Streamlit ici

def scrape_emails(url: str) -> set:
    try:
        resp = requests.get(url, timeout=10)
        emails = re.findall(r"[a-zA-Z0-9.\-_]+@[a-zA-Z0-9.\-_]+\.[a-zA-Z]+", resp.text)
        return set(emails)
    except Exception as e:
        st.error(f"Erreur lors de la récupération des emails : {e}")
        return set()

def scrape_title(url: str) -> str:
    try:
        resp = requests.get(url, timeout=10)
        soup = BeautifulSoup(resp.text, 'html.parser')
        return soup.title.string.strip() if soup.title and soup.title.string else "Aucun titre trouvé"
    except Exception as e:
        st.error(f"Erreur lors de la récupération du titre : {e}")
        return "Erreur"

def run_web_recon(url: str):
    st.subheader("Résultat Web Reconnaissance")
    
    title = scrape_title(url)
    st.write(f"**Titre de la page :** {title}")

    emails = scrape_emails(url)
    if emails:
        st.write("**Emails trouvés :**")
        for email in emails:
            st.write(f"📧 {email}")
    else:
        st.write("Aucun email trouvé.")
