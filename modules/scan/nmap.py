
import subprocess
import shlex
from pathlib import Path
from typing import Tuple

def run_nmap_scan(target: str, user_args: str = "") -> Tuple[str, str]:
    
    # Répertoire de sauvegarde du XML
    output_dir = Path("/home/sam/pen_ia/modules/analyzer/data")
    output_dir.mkdir(parents=True, exist_ok=True)  # crée le dossier si inexistant
    xml_path = output_dir / "metasploitable_host2.xml"

    # Assemble la commande Nmap : les options de l'utilisateur + toujours -oX xml_path
    cmd = ["nmap"] + shlex.split(user_args) + ["-oX", str(xml_path), target]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return proc.stdout, str(xml_path)
    except subprocess.CalledProcessError as e:
        return f"[ERREUR NMAP]\n{return_error(e)}", str(xml_path)

def return_error(e):
    try:
        return e.stdout + "\n" + e.stderr
    except:
        return str(e)