import streamlit as st

# Configuration de la page
st.set_page_config(page_title="PenTest Tools - Pen IA", layout="wide")

# En-tête principal avec emoji
st.markdown("## 🛡️ Pen IA - Framework de Pentest Assisté par IA")
st.markdown("Bienvenue dans **Pen IA**, votre outil de test de pénétration intelligent. "
            "Ce framework combine les techniques classiques de pentest avec l'intelligence artificielle pour :")
st.markdown("- 🔍 Reconnaissance automatisée") 
st.markdown("- ⚡ Analyse des vulnérabilités") 
st.markdown("- 🤖 Priorisation intelligente des cibles") 
st.markdown("---")

# Section Outils de Reconnaissance
st.markdown("### 🕵️‍♂️ Outils de Reconnaissance")
st.markdown("Ces outils vous aident à collecter des informations sur les cibles, comme les sous-domaines, "
            "les bannières de services, ou encore les emails associés à un domaine.")

st.markdown("Exemples :")
st.markdown("- 🌐 **Web Reconnaissance** : collecte des titres, meta-data et emails")
st.markdown("- 📡 **Ping / NSLookup / Whois** : informations DNS et réseau")
st.markdown("- 📝 **Banner Grabbing** : récupère les bannières des services ouverts")
st.markdown("- 📧 **theHarvester** : collecte d'emails et sous-domaines")
st.markdown("- 🌍 **WhatWeb** : identification des technologies web utilisées")

st.markdown("---")

# Section Outils de Scan
st.markdown("### 🖥️ Outils de Scan & Analyse de Vulnérabilités")
st.markdown("Ces outils vous permettent de scanner les systèmes, identifier les services et détecter les failles potentielles.")

st.markdown("Exemples :")
st.markdown("- 🕸️ **Nmap** : scanner réseau et services")
st.markdown("- 💻 **Nikto** : scanner de vulnérabilités web")
st.markdown("- 🐍 **Metasploit** : exploitation et sessions Meterpreter")

st.markdown("---")

# Pied de page
st.markdown("💡 *Pen IA combine la puissance du pentest classique avec l'IA pour optimiser vos audits de sécurité.*")
st.markdown("📌 Développé par l'équipe Pen IA pour faciliter les tests de pénétration automatisés.")
