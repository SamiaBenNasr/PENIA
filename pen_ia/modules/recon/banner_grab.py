# modules/recon/banner_grab.py
import socket
import streamlit as st

def banner_grab(target: str, port: int = 80, timeout: float = 5.0) -> str:
    """Capture la bannière d’un service à la cible spécifiée."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((target, port))
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "Pas de bannière"
    except Exception as e:
        return None  # Retourne None si pas de connexion

def run_banner_grab(targets=None, ports=None, streamlit_mode=False):
    """Exécute le banner grab sur plusieurs cibles/ports et affiche seulement ceux qui répondent."""
    if targets is None:
        targets = ['tryhackme.com', '192.168.1.10']
    if ports is None:
        ports = [80, 443, 22, 21]

    results = []
    for t in targets:
        for p in ports:
            banner = banner_grab(t, p)
            if banner is not None:  # Seulement si connexion OK
                results.append((t, p, banner))
                if streamlit_mode:
                    st.write(f"[{t}:{p}] → {banner}")
                else:
                    print(f"[{t}:{p}] → {banner}")
    return results
