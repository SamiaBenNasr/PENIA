import streamlit as st
from modules.scan.nikto import run_nikto_scan
from modules.scan.nmap import run_nmap_scan

st.set_page_config(page_title="Pen IA - Scan & Vuln", layout="wide")
st.markdown("## 🛡️ Outils de Scan & Analyse de Vulnérabilités")
st.markdown("Effectuez des scans réseau, détectez les vulnérabilités et interagissez avec vos cibles de manière automatisée.")
st.markdown("-")

option_scan = st.selectbox("Choisis une option :", [
    "Sélectionne...",
    "🌐 Scan Réseau avec Nmap",
    "🔍 Scan de vulnérabilités avec Nikto",
])

if option_scan == "🌐 Scan Réseau avec Nmap":
    st.subheader("🌐 Scanner le réseau avec Nmap")
    st.markdown("📡 Réalisez un scan complet des ports et services d'une IP ou d'une plage d'IP.")
    cible = st.text_input("Entrez l’adresse IP ou la plage (ex: 192.168.1.4 ou 192.168.1.0/24)", value="192.168.0.111", key="nmap_cible")
    options = st.text_input("Options Nmap (ex: -sS -p 1-1000)", value="-sV", key="nmap_options")
    if st.button("Lancer le scan", key="nmap_button"):
        if cible:
            with st.spinner("Scan en cours..."):
                resultat = run_nmap_scan(cible, options)
                st.code(resultat)
                st.success(f"✅ Scan Nmap terminé pour {cible}")
                st.download_button("📥 Télécharger le rapport", data=resultat, file_name="nmap_result.txt")
        else:
            st.warning("Veuillez entrer une cible valide.")

elif option_scan == "🔍 Scan de vulnérabilités avec Nikto":
    st.subheader("🔍 Scanner le site avec Nikto")
    st.markdown("🕵️ Analyse de vulnérabilités web et découverte des failles communes sur un site.")
    cible = st.text_input("Entrez l’URL du site (ex: http://testphp.vulnweb.com)", value="http://localhost", key="nikto_cible")
    if st.button("Lancer le scan", key="nikto_button"):
        if cible:
            run_nikto_scan(cible)
            st.success(f"✅ Scan Nikto terminé pour {cible}")
        else:
            st.warning("Veuillez entrer une URL valide.")

