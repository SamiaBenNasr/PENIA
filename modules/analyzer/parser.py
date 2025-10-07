import xml.etree.ElementTree as ET
import pandas as pd
import re
from pathlib import Path
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET

xml_file = "/home/sam/pen_ia/modules/analyzer/data/metasploitable_host.xml"

with open(xml_file, "r", encoding="utf-8") as f:
    xml_content = f.read()

# Utiliser le parser lxml
soup = BeautifulSoup(xml_content, "lxml-xml")  # attention au '-xml'
fixed_xml = soup.prettify()

fixed_file = "/home/sam/pen_ia/modules/analyzer/data/metasploitable_host_fixed.xml"
with open(fixed_file, "w", encoding="utf-8") as f:
    f.write(fixed_xml)





output_csv = Path("/home/sam/pen_ia/modules/analyzer/data/nmap_data_fixed2.csv")

def strip_ns(tag):
    """Retire un namespace si présent: '{...}tag' -> 'tag'"""
    return tag.split('}', 1)[-1] if '}' in tag else tag

def expand_port_str(port_str):
    """Renvoie une liste de ports à partir d'une entrée comme '3-5' ou '21'."""
    ports = []
    for part in port_str.split(','):
        part = part.strip()
        if not part:
            continue
        if '-' in part:
            start, end = part.split('-', 1)
            try:
                s = int(start); e = int(end)
                ports.extend(range(s, e+1))
            except ValueError:
                continue
        else:
            try:
                ports.append(int(part))
            except ValueError:
                continue
    return ports

# Parser l'XML
try:
    tree = ET.parse(fixed_file)
except ET.ParseError as e:
    print(f"[ERROR] échec du parsing du fichier {fixed_file}: {e}")
    raise

root = tree.getroot()
print(f"[INFO] root tag: {strip_ns(root.tag)}")

# Recherche de tous les hôtes (peu importe où ils sont dans l'arbre)
hosts = root.findall('.//host')
print(f"[INFO] nombre d'éléments <host> trouvés: {len(hosts)}")

data = []

for idx, host in enumerate(hosts, start=1):
    # Trouver une adresse IPv4 (attrib 'addr'), prioriser addrtype="ipv4" si présent
    addr = None
    # recherche d'abord une address avec addrtype ipv4
    addr_elem = host.find('.//address[@addr][@addrtype="ipv4"]')
    if addr_elem is None:
        # fallback : première address avec 'addr'
        addr_elem = host.find('.//address[@addr]')
    ip = addr_elem.get('addr') if addr_elem is not None else None

    # Trouver tous les port elements (port peut être sous <ports> ou ailleurs)
    port_elems = host.findall('.//port')
    print(f"[DEBUG] host #{idx} ip={ip} - nombre de <port> direct trouvés: {len(port_elems)}")

    for p in port_elems:
        try:
            portid = int(p.get('portid')) if p.get('portid') else None
        except ValueError:
            portid = None
        protocol = p.get('protocol')
        state_elem = p.find('state')
        state = state_elem.get('state') if state_elem is not None else ''
        service_elem = p.find('service')
        service = service_elem.get('name') if service_elem is not None else ''
        version = service_elem.get('version') if service_elem is not None else ''

        # Initialiser les colonnes vulnérabilités
        vuln_ids = []
        vuln_titles = []
        cvss_scores = []
        vuln_descs = []

        # Parcourir les scripts
        for script in p.findall('script'):
            # Cas du script vulners
            if script.get('id') == 'vulners':
                for table in script.findall('table'):
                    # Chaque table représente une vuln
                    vuln_id = table.findtext('elem[@key="id"]') or ''
                    cvss = table.findtext('elem[@key="cvss"]') or ''
                    vuln_ids.append(vuln_id)
                    cvss_scores.append(cvss)
                    vuln_titles.append(table.get('key') or '')  # titre du service/vuln
                    vuln_descs.append(script.get('output') or '')
            else:
                # Cas d'autres scripts (ex: ftp-vsftpd-backdoor)
                title = script.findtext('table/elem[@key="title"]') or ''
                state_s = script.findtext('table/elem[@key="state"]') or ''
                if 'VULNERABLE' in state_s.upper():
                    vuln_ids.append(','.join([e.text for e in script.findall('table/ids/elem')]))
                    vuln_titles.append(title)
                    cvss_scores.append('')  # pas toujours présent
                    vuln_descs.append(script.findtext('table/description/elem') or '')

        # Ajouter la ligne au data
        data.append({
            'ip': ip,
            'protocol': protocol or '',
            'port': portid,
            'state': state,
            'service': service,
            'version': version,
            'vuln_id': ';'.join(vuln_ids),
            'vuln_title': ';'.join(vuln_titles),
            'cvss_score': ';'.join(cvss_scores),
            'vuln_desc': ';'.join(vuln_descs)
        })


    # Gérer les <extraports> (typiquement sur <ports>)
    extraports_nodes = host.findall('.//extraports')
    print(f"[DEBUG] host #{idx} - extraports trouvés: {len(extraports_nodes)}")
    for ex in extraports_nodes:
        # Nmap peut stocker la liste des ports dans l'attrib 'ports'
        ports_attrib = ex.get('ports') or ''
        if ports_attrib:
            ports_list = []
            # ports_attrib peut être "1,3-5,7"
            for token in re.split(r',\s*', ports_attrib.strip()):
                ports_list.extend(expand_port_str(token))
            for pnum in ports_list:
                data.append({
                    'ip': ip,
                    'protocol': ex.get('proto') or 'tcp',  # fallback
                    'port': int(pnum),
                    'state': 'filtered',
                    'service': '',
                    'version': ''
                })
        # parfois les raisons sont dans des éléments <extrareasons> ou <extrareason>
        # on parcourt aussi les enfants pour trouver des attributs 'ports'
        for child in ex:
            child_ports = child.attrib.get('ports')
            if child_ports:
                for pnum in expand_port_str(child_ports):
                    data.append({
                        'ip': ip,
                        'protocol': child.attrib.get('proto') or 'tcp',
                        'port': int(pnum),
                        'state': child.attrib.get('reason', 'filtered'),
                        'service': '',
                        'version': ''
                    })

# Créer DataFrame
df = pd.DataFrame(data)
print(f"[INFO] lignes collectées: {len(df)}")
if df.empty:
    print("[WARN] DataFrame vide — vérifier que le fichier XML fixe contient bien des balises <host> et <port> valides.")
else:
    # Tri et sauvegarde
    df = df.sort_values(['ip', 'port']).reset_index(drop=True)
    df.to_csv(output_csv, index=False)
    print(f"[OK] CSV sauvegardé: {output_csv}")

# Affichage des premières lignes pour debug
print(df.head(30).to_string(index=False))
