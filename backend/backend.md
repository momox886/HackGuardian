# 🛡️ HackGuardian

> Empowering Security, Accelerating Response, Defending Tomorrow.

HackGuardian est une plateforme de gestion et d’analyse de vulnérabilités CVE (Common Vulnerabilities and Exposures) en temps réel. Elle intègre un tableau de bord interactif, un système de messagerie chiffrée (type Messenger), un système de notifications critiques, et une interface d’abonnement à des vendeurs ou produits sensibles. Elle est conçue avec une forte attention à la sécurité, la confidentialité, et l’UX des analystes SOC et développeurs sécurité.

---

## 📊 Stats & Langages

![last commit](https://img.shields.io/badge/last%20commit-today-brightgreen?style=for-the-badge&logo=git)
![html](https://img.shields.io/badge/html-37.6%25-blue?style=for-the-badge&logo=html5)
![languages](https://img.shields.io/badge/languages-4-informational?style=for-the-badge)

## 🛠️ Built with:

![Flask](https://img.shields.io/badge/Flask-black?style=for-the-badge&logo=flask)
![Markdown](https://img.shields.io/badge/Markdown-black?style=for-the-badge&logo=markdown)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-red?style=for-the-badge&logo=sqlalchemy)
![Python](https://img.shields.io/badge/Python-blue?style=for-the-badge&logo=python)

---

## ✨ Fonctionnalités principales

- 🔐 **Authentification sécurisée avec 2FA**
- 🧠 **Enrichissement automatique des CVE**
- 📡 **Système de messagerie en temps réel avec Flask-SocketIO**
- 📦 **Abonnement à des vendeurs spécifiques**
- 📊 **Tableau de bord dynamique avec filtres, DataTables, et vue détaillée**
- 🔔 **Notifications critiques (WebSocket + Email)**
- 🔒 **Chiffrement des données sensibles (AES/GCM) en base de données**
- 🧼 **Filtrage XSS et contenu offensant (niveau serveur et client)**

---

## ⚙️ Architecture technique

### 🧩 Backend
- **Flask** (framework principal)
- **Flask-Login**, **Flask-WTF** pour l'authentification/CSRF
- **Flask-SocketIO** pour la messagerie WebSocket
- **SQLAlchemy** pour l'ORM et PostgreSQL
- **Cryptographie** (Fernet/AES) pour le chiffrement des messages, abonnements et données critiques

### 🎯 Frontend
- **Bootstrap 5** avec **custom CSS** néomorphique & charte Naval Group (bleu marine, rouge, blanc)
- **JavaScript** (vanilla) + **DataTables** pour la gestion dynamique du tableau CVE
- **WebSocket Client** JS pour la messagerie en temps réel

### 🔐 Sécurité
- Chiffrement des messages, utilisateurs, et abonnements à la volée
- Anti-XSS (filtrage DOM + regex serveur)
- Vérification des rôles (admin, superadmin, user) via décorateurs
- CSRF intégré via Flask-WTF

---

## 🚀 Installation locale

```bash
git clone https://github.com/<ton-utilisateur>/hackguardian.git
cd hackguardian
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 backend/run.py 