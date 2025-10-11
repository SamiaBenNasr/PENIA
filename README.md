# PENIA – Outil de Test de Pénétration Automatisé

**Développement d’un outil de test de pénétration automatisé basé sur les étapes d’une cyberattaque**

## Description

PENIA est une application Python développée pour fournir un outil automatisé permettant de simuler les étapes clés d'une cyberattaque, à savoir :

1. **Reconnaissance** : Collecte d'informations publiques sur la cible.
2. **Scan & Analyse des vulnérabilités** : Identification des failles potentielles.
3. **Exploitation** : Tentatives d'accès aux systèmes via des vulnérabilités.
4. **Maintien d'accès / Post-exploitation** : Actions post-intrusion.
5. **Priorisation intelligente des cibles** : Évaluation et hiérarchisation des vulnérabilités détectées à l'aide d'un modèle de machine learning entraîné sur des datasets Nmap et CVSS.

L'application est conçue pour être utilisée dans un environnement de test local ou virtualisé, respectant ainsi un cadre éthique et sécurisé.

## Fonctionnalités

- **Reconnaissance** : Collecte d'informations sur la cible.
- **Scan & Analyse des vulnérabilités** : Intégration de Nmap et Nikto.
- **Exploitation** : Utilisation de Metasploit pour tester les vulnérabilités.
- **Analyse intelligente des vulnérabilités** : Le modèle ML permet de calculer un score de criticité pour chaque vulnérabilité et de prioriser les cibles à exploiter.
