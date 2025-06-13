# 🔐 HackGuardian - Plateforme de Veille de Vulnérabilités

## 📌 Objectif

HackGuardian est une plateforme de **veille de vulnérabilités** conçue pour aider une école à suivre les failles de sécurité critiques affectant les logiciels couramment utilisés.  
Ce projet permet d'automatiser la détection, l'enrichissement, la gestion et la diffusion d'alertes de sécurité.

---

## 🧩 Fonctionnalités principales

- 🕵️‍♂️ Récupération automatisée des CVE liés à des logiciels cibles (via OpenCVE)
- 🔗 Enrichissement via d'autres sources (CERT-FR, exploit-db, etc.)
- 🗃️ Base de données centralisée des vulnérabilités
- 🌐 Interface web pour :
  - Visualisation et filtre des vulnérabilités
  - Accès par gravité, date, produit, etc.
- 🔔 Notifications par email pour les abonnés (quotidien / temps réel)
- 📄 Rapports personnalisables (PDF/HTML)

---

## 🧑‍💻 Répartition des tâches

| Membre | Rôle | Tâches |
|--------|------|--------|
| **Mohamed D.** | Scraping & Veille | Scripts Python pour OpenCVE, CERT-FR et autres sources |
| **Tony F.** | Backend & API | Conception BDD, développement API REST (Flask/FastAPI) |
| **Clayton E.** | Frontend & Notifications | Interface utilisateur, gestion abonnés, alertes mails |

---

## ⚙️ Technologies utilisées

- Python
- Docker / Docker Compose
- PostgreSQL
- Flask ou FastAPI
- HTML/CSS/JS
- Airflow (tâches planifiées)
- SMTP (notifications mail)

---

## 🚀 Lancer le projet

1. Cloner le dépôt :
```bash
git clone https://github.com/momox886/HackGuardian.git
cd HackGuardian
