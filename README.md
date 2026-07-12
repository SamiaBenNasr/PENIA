# PENIA – Automated Penetration Testing Tool

**Development of an automated penetration testing tool based on the stages of a cyberattack**

## Overview

PENIA is a Python application that automates the key stages of a cyberattack within a controlled, ethical testing environment. It integrates industry-standard tools — Nmap, Nikto, and Metasploit — along with a machine learning model for intelligent vulnerability prioritization.

**Main goals:**
- Automate the penetration testing process
- Simulate the stages of a real cyberattack
- Prioritize vulnerabilities using an intelligent scoring system
- Serve as an educational tool for cybersecurity training

## Features

| Stage | Function | Tools/Methods |
|---|---|---|
| 1. Reconnaissance | Gather public information about the target | WHOIS, DNS queries, OSINT |
| 2. Scan & Analysis | Identify potential vulnerabilities | Nmap, Nikto, port analysis |
| 3. Exploitation | Attempt access via vulnerabilities | Metasploit, custom scripts |
| 4. Post-Exploitation | Maintain access, post-intrusion actions | Backdoors, data extraction |
| 5. AI Prioritization | Rank vulnerabilities by risk | ML model trained on Nmap & CVSS datasets |

## Installation

```bash
git clone https://github.com/SamiaBenNasr/PENIA.git
cd PENIA
pip install pipenv
pipenv install
```

External tools required: **Nmap, Nikto, Metasploit Framework** (Linux/WSL2, Python 3.8+). The web interface runs on **Streamlit**.

## Usage

PENIA is built as a **Streamlit web platform** — `PENIA.py` launches the interactive interface (no CLI flags required):

```bash
streamlit run PENIA.py
```

The platform provides a dashboard with dedicated pages for each stage of the workflow:

- 🕵️ **Reconnaissance** — Web Recon, Ping/NSLookup/Whois, Banner Grabbing, theHarvester, WhatWeb
- 🖥️ **Scan & Vulnerability Analysis** — Nmap, Nikto
- 🐍 **Exploitation** — Metasploit / Meterpreter sessions
- 🤖 **Prioritizer** — ML-based CVSS score estimation and risk-ranked target reports

## Machine Learning Model

The vulnerability prioritization module uses a **regression pipeline** built with scikit-learn and XGBoost to predict a CVSS-based risk score for each detected vulnerability.

- **Input features:** port, protocol, service, product, version, CPE, exploit type, exploit availability, CVE list, reference links, exploit ID
- **Target:** average CVSS score
- **Preprocessing:** mean imputation for numerical features; constant imputation + one-hot encoding for low-cardinality categorical features, bundled via a `ColumnTransformer`
- **Model:** `XGBRegressor` (1000 estimators, learning rate 0.05) inside a scikit-learn `Pipeline`, benchmarked against a `RandomForestRegressor` baseline
- **Evaluation:** 5-fold cross-validation using Mean Absolute Error (MAE)
- **Output:** the trained pipeline is serialized with `joblib` as `cvss_predictor.pkl` and loaded at runtime to score and rank newly discovered vulnerabilities

Training data comes from Nmap scan exports and CVSS reference scores.

## Ethical Notice

PENIA is intended strictly for educational and testing purposes in **authorized, local, or virtualized environments**. Unethical or unauthorized use is strictly prohibited; the author assumes no liability for misuse.

## License

MIT License

---
**Author:** Samia Ben Nasr | **GitHub:** [@SamiaBenNasr](https://github.com/SamiaBenNasr)
