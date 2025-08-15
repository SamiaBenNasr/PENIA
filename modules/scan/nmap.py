

import subprocess
import streamlit as st

def run_nmap_scan(target: str, args: str = "-sS"):
    try:
        command = ["nmap"] + args.split() + [target]
        output = subprocess.check_output(command, stderr=subprocess.STDOUT)
        return output.decode()
    except subprocess.CalledProcessError as e:
        return f"[ERREUR NMAP] {e.output.decode()}"
