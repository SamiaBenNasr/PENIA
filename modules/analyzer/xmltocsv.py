import xml.etree.ElementTree as ET
import csv
import re

xml_file = "/home/sam/pen_ia/modules/analyzer/data/metasploitable_host.xml"
csv_file = "/home/sam/pen_ia/modules/analyzer/data/nmap_vuln_detailed.csv"

tree = ET.parse(xml_file)
root = tree.getroot()

rows = []

for port in root.findall(".//port"):
    portid = port.attrib.get("portid")
    protocol = port.attrib.get("protocol")

    service = port.find("service")
    service_name = service.attrib.get("name") if service is not None else ""
    product = service.attrib.get("product") if service is not None else ""
    version = service.attrib.get("version") if service is not None else ""
    cpe = service.find("cpe").text if service is not None and service.find("cpe") is not None else ""

    for script in port.findall("script"):
        vuln_id = script.attrib.get("id", "")
        output = script.attrib.get("output", "")

        # Recherche des CVE et CVSS dans le texte
        cve_list = re.findall(r"(CVE-\d{4}-\d+)", output)
        cvss_list = re.findall(r"\b\d+\.\d+\b", output)

        title = ""
        state = ""
        description = ""
        refs = []
        exploit_id = ""
        exploit_type = ""
        is_exploit = ""
        cvss = ""

        # Parcours récursif de tous les sous-éléments
        for elem in script.findall(".//elem"):
            key = elem.attrib.get("key", "")
            text = (elem.text or "").strip()

            if key == "title":
                title = text
            elif key == "state":
                state = text
            elif "description" in key:
                description += text + " "
            elif "refs" in key or text.startswith("http"):
                refs.append(text)
            elif key == "id":
                exploit_id = text
            elif key == "type":
                exploit_type = text
            elif key == "is_exploit":
                is_exploit = text
            elif key == "cvss":
                cvss = text

        # Si plusieurs <table>, on génère une ligne par vulnérabilité interne
        tables = script.findall(".//table")
        if tables:
            for t in tables:
                local_exploit_id = ""
                local_type = ""
                local_cvss = ""
                local_is_exploit = ""

                for e in t.findall(".//elem"):
                    key = e.attrib.get("key", "")
                    text = (e.text or "").strip()

                    if key == "id":
                        local_exploit_id = text
                    elif key == "type":
                        local_type = text
                    elif key == "cvss":
                        local_cvss = text
                    elif key == "is_exploit":
                        local_is_exploit = text

                if local_exploit_id or local_type:
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
                        "exploit_id": local_exploit_id,
                        "exploit_type": local_type,
                        "exploit_cvss": local_cvss,
                        "is_exploit": local_is_exploit
                    })
        else:
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
                "exploit_cvss": cvss,
                "is_exploit": is_exploit
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
