# modules/recon/whatweb_scan.py
import subprocess
import streamlit as st
from io import BytesIO

def save_results_to_memory(results: str, filename: str):
    """Permet de télécharger un rapport en mémoire."""
    buffer = BytesIO()
    buffer.write(results.encode())
    buffer.seek(0)
    st.download_button(
        label="📥 Télécharger le rapport",
        data=buffer,
        file_name=filename,
        mime="text/plain"
    )

def run_whatweb_scan(target: str, level: int = 1):
    """Scan WhatWeb pour une seule cible avec affichage Streamlit et téléchargement."""
    st.info(f"[+] Analyse de {target} avec WhatWeb (niveau {level})...")
    try:
        result = subprocess.run(
            ["whatweb", "-a", str(level), target],
            capture_output=True, text=True, timeout=30
        )

        output_text = ""
        if result.stdout:
            st.subheader("📄 Résultat WhatWeb")
            st.code(result.stdout)
            output_text += result.stdout
        if result.stderr:
            st.error(f"Erreur : {result.stderr}")
            output_text += "\n[Erreur] " + result.stderr
        if not result.stdout and not result.stderr:
            msg = "Aucun résultat. L’URL est peut-être incorrecte ou injoignable."
            st.warning(msg)
            output_text += msg

        # Bouton de téléchargement
        save_results_to_memory(output_text, f"whatweb_{target.replace('.', '_')}.txt")

    except subprocess.TimeoutExpired:
        st.error("[-] Le scan WhatWeb a expiré.")
    except Exception as e:
        st.error(f"[-] Erreur: {e}")

def run_whatweb_ip_range(ip_range, aggressiveness=3, output_file="resultats.log"):
    """Scan WhatWeb pour une plage IP avec affichage et téléchargement."""
    st.info(f"[+] Scan de la plage {ip_range} avec WhatWeb (niveau {aggressiveness})...\n")
    try:
        result = subprocess.run(
            [
                "whatweb",
                "-a", str(aggressiveness),
                "--no-errors",
                ip_range
            ],
            capture_output=True, text=True
        )

        output_text = ""
        if result.stdout:
            st.subheader("📄 Résultats WhatWeb (Plage IP)")
            st.code(result.stdout)
            output_text += result.stdout
        if result.stderr:
            st.error(f"Erreur : {result.stderr}")
            output_text += "\n[Erreur] " + result.stderr

        save_results_to_memory(output_text, output_file)

    except Exception as e:
        st.error(f"[!] Erreur pendant le scan de plage IP : {e}")
