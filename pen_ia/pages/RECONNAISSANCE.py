import streamlit as st
from modules.recon.web_recon import run_web_recon
from modules.recon.info_gathering import run_info_gathering
from modules.recon.whatweb_scan import run_whatweb_scan, run_whatweb_ip_range
from modules.recon.theharvester_scan import run_theharvester
from modules.recon.banner_grab import run_banner_grab

# Configuration de la page
st.set_page_config(page_title="Pen IA - Outils de Reconnaissance", layout="wide")

# Header
st.markdown("## 🕵️‍♂️ Outils de Reconnaissance - Pen IA")
st.markdown("Collectez des informations sur vos cibles grâce à des outils automatisés et puissants.")
st.markdown("---")

# Sélection de l'outil
option = st.selectbox("Choisis un outil :", [
    "Sélectionne...",
    "🌐 Web Reconnaissance (email, title)",
    "📝 Banner Grabbing",
    "📡 Ping / NSLookup / Whois",
    "🌍 WhatWeb Scan (URL)",
    "📊 WhatWeb Scan (Plage IP)",
    "📧 Collecte emails avec theHarvester"
])

# --- Web Reconnaissance ---
if option == "🌐 Web Reconnaissance (email, title)":
    st.markdown("**Web Recon** : collecte des titres, meta-data et emails d'un site.")
    url = st.text_input("Entrez l’URL (ex: http://tryhackme.com)", value="http://tryhackme.com", key="web_url")
    if st.button("Lancer Web Recon", key="web_button"):
        if url:
            run_web_recon(url)
            st.success(f"✅ Scan Web Recon lancé sur : {url}")
        else:
            st.warning("Veuillez entrer une URL.")

# --- Banner Grabbing ---
elif option == "📝 Banner Grabbing":
    st.markdown("**Banner Grabbing** : récupère les bannières des services ouverts.")
    targets = st.text_input("Cibles séparées par virgule (ex: tryhackme.com,192.168.1.10)",value="192.168.0.111",key="banner_targets")
    max_port = st.number_input("Port maximum", min_value=1, max_value=65535, value=30, key="banner_max_port")

    if st.button("Lancer Banner Grab", key="banner_button"):
        if targets:
            target_list = [t.strip() for t in targets.split(",")]
            port_list = list(range(0, max_port + 1))
            st.info(f"**Scan de {targets} de 0 à {max_port}...**")
            run_banner_grab(target_list, port_list, streamlit_mode=True)
            st.success("✅ Scan terminé")
        else:
            st.warning("Veuillez remplir le champ des cibles.")

# --- Ping / NSLookup / Whois ---
elif option == "📡 Ping / NSLookup / Whois":
    st.markdown("**Info Gathering** : collecte des informations réseau et DNS.")
    host = st.text_input("Entrez le domaine ou IP cible", value="192.168.0.111", key="host_input")
    if st.button("Lancer Info Gathering", key="host_button"):
        if host:
            run_info_gathering(host)
            st.success(f"✅ Info Gathering lancé sur : {host}")
        else:
            st.warning("Veuillez entrer un hôte.")

# --- WhatWeb Scan (URL) ---
elif option == "🌍 WhatWeb Scan (URL)":
    st.markdown("**WhatWeb URL** : scanner d’empreintes web avec différents niveaux d’agressivité.")
    url = st.text_input("Entrez l’URL (ex: collegecdi.ca)", value="http://collegecdi.ca", key="whatweb_url")
    level = st.selectbox("Niveau d’agressivité", [1, 2, 3], index=0, key="whatweb_level")
    if st.button("Lancer WhatWeb Scan", key="whatweb_button"):
        if url:
            if not url.startswith("http://") and not url.startswith("https://"):
                url = "http://" + url
            run_whatweb_scan(url, level)
            st.success(f"✅ WhatWeb scan lancé sur : {url}")
        else:
            st.warning("Veuillez entrer une URL.")

# --- WhatWeb Scan (Plage IP) ---
elif option == "📊 WhatWeb Scan (Plage IP)":
    st.markdown("**WhatWeb IP Range** : scanner d’empreintes web sur une plage d’IP.")
    ip_range = st.text_input("Entrez la plage d’IP (ex: 192.168.1.0/24)", value="192.168.0.111", key="ip_range")
    level = st.selectbox("Niveau d’agressivité", [1, 2, 3], index=2, key="ip_level")
    output_file = st.text_input("Nom du fichier de sortie", value="resultats.log", key="ip_output")
    if st.button("Lancer Scan IP Range", key="ip_button"):
        run_whatweb_ip_range(ip_range, str(level), output_file)
        st.success(f"✅ Scan IP Range lancé sur : {ip_range}")

# --- TheHarvester ---
elif option == "📧 Collecte emails avec theHarvester":
    st.markdown("**theHarvester** : collecte des emails et sous-domaines d’un domaine cible.")
    domain = st.text_input("Entrez le domaine cible (ex: example.com)",value="tryhackme.com", key="harvester_domain")
    source = st.text_input("Source (ex: all, google, bing, twitter)", value="google", key="harvester_source")
    limit = st.number_input("Nombre max de résultats", min_value=1, value=10, key="harvester_limit")
    if st.button("Lancer theHarvester", key="harvester_button"):
        run_theharvester(domain, source, limit)
        st.success(f"✅ theHarvester lancé sur : {domain}")
