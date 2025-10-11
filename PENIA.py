import streamlit as st

st.set_page_config(page_title="PenTest Tools - Pen IA", layout="wide")

st.markdown("## 🛡️ Pen IA - Framework de Pentest Assisté par IA")
st.markdown("Bienvenue dans **Pen IA**, votre outil de test de pénétration intelligent. "
            "Ce framework combine les techniques classiques de pentest avec l'intelligence artificielle pour :")
st.markdown("- 🔍 Reconnaissance automatisée") 
st.markdown("- ⚡ Analyse des vulnérabilités") 
st.markdown("- 🤖 Priorisation intelligente des cibles") 
st.markdown("---")

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

st.markdown("### 🖥️ Outils de Scan & Analyse de Vulnérabilités")
st.markdown("Ces outils vous permettent de scanner les systèmes, identifier les services et détecter les failles potentielles.")
st.markdown("Exemples :")
st.markdown("- 🕸️ **Nmap** : scanner réseau et services")
st.markdown("- 💻 **Nikto** : scanner de vulnérabilités web")
st.markdown("- 🐍 **Metasploit** : exploitation et sessions Meterpreter")
st.markdown("---")

st.markdown("### 🤖 Priorisation Intelligente des Cibles (Prioritizer)")
st.markdown("Grâce à notre **modèle de Machine Learning**, Pen IA évalue automatiquement les vulnérabilités détectées "
            "et leur attribue un **score CVSS estimé**, permettant de :")
st.markdown("- ⚡ Prioriser les vulnérabilités critiques à exploiter en premier")
st.markdown("- 📊 Générer des rapports enrichis avec un classement des cibles selon le risque")
st.markdown("- 🔗 Faciliter la prise de décision pour l'équipe de sécurité")
st.markdown("Le Prioritizer utilise des **features extraites des scans Nmap/Nikto/Metasploit**, telles que les ports, services, versions, CPE et types d'exploits, pour prédire un score de vulnérabilité moyen et guider vos audits.")
st.markdown("---")

st.markdown("💡 *Pen IA combine la puissance du pentest classique avec l'IA pour optimiser vos audits de sécurité.*")
st.markdown("📌 Développé par l'équipe Pen IA pour faciliter les tests de pénétration automatisés.")
