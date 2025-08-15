# modules/recon/theharvester_scan.py
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

def run_theharvester(domain: str, source: str = "all", limit: int = 100):
    st.info(f"[+] Lancement de TheHarvester sur {domain} avec source {source} (limit={limit})")
    output_text = ""
    try:
        result = subprocess.run(
            ["theHarvester", "-d", domain, "-b", source, "-l", str(limit)],
            capture_output=True,
            text=True,
            timeout=60
        )
        if result.stdout:
            output_text += result.stdout
            st.subheader("📄 Résultats TheHarvester")
            st.text_area("Résultat complet", result.stdout, height=300)
        if result.stderr:
            output_text += "\n[Erreur] " + result.stderr
            st.error(f"Erreur : {result.stderr}")
        if not result.stdout and not result.stderr:
            msg = "⚠️ Aucun résultat trouvé ou domaine incorrect."
            st.warning(msg)
            output_text += msg

        # Bouton pour télécharger le rapport
        save_results_to_memory(output_text, f"theharvester_{domain.replace('.', '_')}.txt")

    except subprocess.TimeoutExpired:
        st.error("[-] TheHarvester a expiré.")
    except Exception as e:
        st.error(f"[-] Erreur: {e}")
