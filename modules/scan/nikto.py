import subprocess
import streamlit as st

def run_nikto_scan(target: str):
    st.subheader("🔍 Résultat du scan Nikto")

    target_clean = target.replace("http://", "").replace("https://", "")

    try:
        result = subprocess.run(
            ["nikto", "-h", target_clean],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )

        output = (result.stdout or "") + "\n" + (result.stderr or "")

        if not output.strip():
            st.warning("⚠️ Aucun résultat. Vérifiez l’URL ou votre connexion.")
        else:
            st.code(output)
            st.download_button(
                label="💾 Télécharger le rapport",
                data=output,
                file_name=f"nikto_{target_clean.replace('/', '_')}.txt",
                mime="text/plain"
            )

    except subprocess.TimeoutExpired:
        st.error("[-] Nikto a expiré.")
    except Exception as e:
        st.error(f"Erreur inattendue lors du scan Nikto: {e}")
