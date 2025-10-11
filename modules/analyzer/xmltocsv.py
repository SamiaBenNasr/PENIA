# modules/analyzer/xmltocsv.py
import xml.etree.ElementTree as ET
import csv
import re
from pathlib import Path

def convert_xml_to_csv(xml_file: str, csv_file: str):
    """
    Convertit un fichier XML Nmap en CSV détaillé pour analyse des vulnérabilités.
    Gère les ports avec ou sans scripts.

    Args:
        xml_file (str): Chemin vers le fichier XML généré par Nmap.
        csv_file (str): Chemin vers le fichier CSV à générer.
    """
    xml_path = Path(xml_file)
    if not xml_path.exists():
        raise FileNotFoundError(f"Le fichier XML n'existe pas : {xml_file}")

    tree = ET.parse(xml_file)
    root = tree.getroot()
    rows = []

    # Parcours de tous les ports
    for port in root.findall(".//port"):
        portid = port.attrib.get("portid", "")
        protocol = port.attrib.get("protocol", "")

        service = port.find("service")
        service_name = service.attrib.get("name") if service is not None else ""
        product = service.attrib.get("product") if service is not None else ""
        version = service.attrib.get("version") if service is not None else ""
        cpe = service.find("cpe").text if service is not None and service.find("cpe") is not None else ""
        state = port.find("state").attrib.get("state", "") if port.find("state") is not None else ""

        # Vérifie s'il y a des scripts
        scripts = port.findall("script")
        if scripts:
            for script in scripts:
                vuln_id = script.attrib.get("id", "")
                output = script.attrib.get("output", "")

                # Recherche CVE et CVSS dans le texte
                cve_list = re.findall(r"(CVE-\d{4}-\d+)", output)
                cvss_list = re.findall(r"\b\d+\.\d+\b", output)

                title = ""
                description = ""
                refs = []
                exploit_id = ""
                exploit_type = ""
                exploit_cvss = ""
                is_exploit = ""

                for elem in script.findall(".//elem"):
                    key = elem.attrib.get("key", "")
                    text = (elem.text or "").strip()
                    if key == "title":
                        title = text
                    elif "description" in key:
                        description += text + " "
                    elif "refs" in key or text.startswith("http"):
                        refs.append(text)
                    elif key == "id":
                        exploit_id = text
                    elif key == "type":
                        exploit_type = text
                    elif key == "cvss":
                        exploit_cvss = text
                    elif key == "is_exploit":
                        is_exploit = text

                rows.append({
                    "port": portid,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "cpe": cpe,
                    "script_id": vuln_id,
                    "title": title,
                    "state": state,
                    "description": description.strip(),
                    "cve_list": ", ".join(set(cve_list)),
                    "cvss_list": ", ".join(set(cvss_list)),
                    "ref_links": ", ".join(set(refs)),
                    "exploit_id": exploit_id,
                    "exploit_type": exploit_type,
                    "exploit_cvss": exploit_cvss,
                    "is_exploit": is_exploit
                })
        else:
            # Aucun script → ajoute le port quand même
            rows.append({
                "port": portid,
                "protocol": protocol,
                "service": service_name,
                "product": product,
                "version": version,
                "cpe": cpe,
                "script_id": "",
                "title": "",
                "state": state,
                "description": "",
                "cve_list": "",
                "cvss_list": "",
                "ref_links": "",
                "exploit_id": "",
                "exploit_type": "",
                "exploit_cvss": "",
                "is_exploit": ""
            })

    # Écriture CSV
    fieldnames = [
        "port", "protocol", "service", "product", "version", "cpe",
        "script_id", "title", "state", "description",
        "cve_list", "cvss_list", "ref_links",
        "exploit_id", "exploit_type", "exploit_cvss", "is_exploit"
    ]

    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[✔] CSV généré : {csv_file}")
    print(f"[+] Nombre total de lignes : {len(rows)}")
