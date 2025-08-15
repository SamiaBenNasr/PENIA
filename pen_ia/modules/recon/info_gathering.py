import subprocess
import streamlit as st
from io import BytesIO

def run_ping(host: str) -> str:
    try:
        output = subprocess.check_output(["ping", "-c", "3", host], stderr=subprocess.STDOUT)
        result = output.decode()
        st.subheader("📶 PING")
        st.code(result)
        return "=== PING ===\n" + result
    except subprocess.CalledProcessError as e:
        error = f"Erreur ping: {e.output.decode()}"
        st.error(error)
        return "=== PING ===\n" + error

import ipaddress

def run_nslookup(host: str) -> str:
    try:
        # Si c'est une IP privée, on skip
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private:
                msg = "NSLOOKUP ignoré pour les IP privées."
                st.warning(msg)
                return "=== NSLOOKUP ===\n" + msg
        except ValueError:
            pass  # C'est un nom de domaine, pas une IP

        output = subprocess.check_output(["nslookup", host], stderr=subprocess.STDOUT)
        result = output.decode()
        st.subheader("🧭 NSLOOKUP")
        st.code(result)
        return "=== NSLOOKUP ===\n" + result

    except subprocess.CalledProcessError as e:
        error = f"Erreur nslookup: {e.output.decode()}"
        st.error(error)
        return "=== NSLOOKUP ===\n" + error


def run_whois(host: str) -> str:
    try:
        output = subprocess.check_output(["whois", host], stderr=subprocess.STDOUT)
        result = output.decode()
        st.subheader("👤 WHOIS")
        st.code(result)
        return "=== WHOIS ===\n" + result
    except subprocess.CalledProcessError as e:
        error = f"Erreur whois: {e.output.decode()}"
        st.error(error)
        return "=== WHOIS ===\n" + error

def save_results_to_memory(results: str, filename: str):
    buffer = BytesIO()
    buffer.write(results.encode())
    buffer.seek(0)
    st.download_button(
        label="📥 Télécharger le rapport",
        data=buffer,
        file_name=filename,
        mime="text/plain"
    )

def run_info_gathering(target: str):
    st.header(f"🔍 Information Gathering pour {target}")
    
    # Collecte des résultats
    results = ""
    results += run_ping(target) + "\n\n"
    results += run_nslookup(target) + "\n\n"
    results += run_whois(target) + "\n\n"
    
    # Sauvegarde et téléchargement
    filename = f"info_gathering_{target.replace('.', '_')}.txt"
    save_results_to_memory(results, filename)
