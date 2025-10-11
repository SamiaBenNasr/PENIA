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

# --- branch Nmap corrigée (remplace la partie Nmap de ton code) ---
if option_scan == "🌐 Scan Réseau avec Nmap":
    st.subheader("🌐 Scanner le réseau avec Nmap")
    st.markdown("📡 Réalisez un scan complet des ports et services d'une IP ou d'une plage d'IP.")
    cible = st.text_input("Entrez l’adresse IP ou la plage (ex: 192.168.1.4 ou 192.168.1.0/24)",
                          value="192.168.252.209", key="nmap_cible")
    options = st.text_input(
        "Options Nmap (ex: -sV --script vuln,vulners)",
        value="-sV --script vuln,vulners", key="nmap_options"
    )

    # Bouton de scan : lance nmap et sauvegarde le résultat dans st.session_state
    if st.button("Lancer le scan", key="nmap_button"):
        if not cible:
            st.warning("Veuillez entrer une cible valide.")
        else:
            with st.spinner("Scan en cours..."):
                try:
                    stdout_text, xml_path = run_nmap_scan(cible, options)
                    # Sauvegarder dans session_state pour garder l'info après rerun
                    st.session_state['scan_done'] = True
                    st.session_state['scan_stdout'] = stdout_text
                    st.session_state['xml_path'] = xml_path
                    st.success(f"✅ Scan Nmap terminé pour {cible}")
                except Exception as e:
                    st.error(f"Erreur pendant le scan : {e}")
                    st.session_state['scan_done'] = False

    # Si un scan a été réalisé dans cette session (ou si xml_path existe dans session), afficher résultat & option conversion
    if st.session_state.get('scan_done'):
        st.markdown("#### Résultat du scan")
        if 'scan_stdout' in st.session_state:
            st.code(st.session_state['scan_stdout'])
            st.download_button(
                "📥 Télécharger le rapport texte",
                data=st.session_state['scan_stdout'],
                file_name="nmap_result.txt",
                mime="text/plain"
            )

        xml_path = st.session_state.get('xml_path')
        st.info(f"📂 Fichier XML sauvegardé ici : `{xml_path}`")

        # --- Section conversion visible tout le temps après le scan ---
        st.markdown("### Conversion XML → CSV")
        st.write("Veux-tu convertir le XML généré en CSV pour l'analyse des vulnérabilités ?")
        convertir = st.radio(
            "Choix :",
            ("Non", "Oui"),
            key="convert_choice"  # clé persistante dans session_state
        )

        if convertir == "Oui":
            # On affiche le bouton de conversion (action explicite)
            if st.button("Convertir maintenant", key="convert_now"):
                # chemin de sortie CSV que tu veux
                csv_path = "/home/sam/pen_ia/modules/analyzer/data/test2.csv"
                try:
                    from modules.analyzer.xmltocsv import convert_xml_to_csv
                    # utiliser le xml_path sauvegardé
                    convert_xml_to_csv(xml_path, csv_path)
                    st.success(f"✅ Conversion réussie ! Fichier CSV sauvegardé ici : `{csv_path}`")

                    # afficher aperçu et proposer téléchargement
                    import pandas as pd
                    df = pd.read_csv(csv_path)
                    st.dataframe(df.head(20))
                    with open(csv_path, "rb") as f:
                        st.download_button(
                            "📥 Télécharger le fichier CSV",
                            data=f,
                            file_name="nmap_vuln_detailed.csv",
                            mime="text/csv"
                        )
                except Exception as e:
                    st.error(f"❌ Échec de la conversion XML → CSV : {e}")
        else:
            st.info("La conversion XML → CSV n'a pas été demandée.")


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

