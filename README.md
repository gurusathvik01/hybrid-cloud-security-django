🔐 Hybrid Cloud Security System (Django)

Author: Guru Sathvik
Role: Full-Stack / Backend Developer
Tech Focus: Cloud Security, Django, Secure File Systems

📌 Project Overview

Hybrid Cloud Security System is a Django-based web application designed to demonstrate secure file handling, access control, and audit logging in a hybrid cloud environment.

The project focuses on real-world security concepts such as authentication, encryption, access tracking, and environment-based secret management, making it suitable for cloud, backend, and security-focused roles.

🎯 Key Objectives

Implement secure user authentication (Admin & User roles)

Protect sensitive files using encryption and controlled access

Maintain audit logs for security monitoring

Demonstrate secure GitHub practices (no secrets in repo)

Simulate hybrid cloud storage behavior

✨ Features

🔑 Role-based authentication (Admin / User)

📁 Secure file upload & access control

🔐 Encryption utilities for sensitive data

🧾 Access logging for audit & monitoring

🌐 Environment variable–based secret management

🧼 Clean GitHub repository (no hardcoded secrets)

🛠 Tech Stack

Backend: Python, Django

Frontend: HTML, Django Templates

Database: SQLite

Security: Encryption utilities, access logs

Tools: Git, GitHub

🗂 Project Structure
hybrid-cloud-security/
│
├── hybrid_cloud_security/     # Django project configuration
├── securityapp/               # Core application logic
│   ├── models.py              # Database models
│   ├── views.py               # Business logic
│   ├── utils/                 # Security & utility modules
│   ├── templates/             # HTML templates
│   └── migrations/            # Database migrations
│
├── manage.py
├── .gitignore
└── README.md

🔒 Security Notes

❌ No secret keys stored in the repository

✅ Sensitive files excluded using .gitignore

✅ Environment variables used for configuration

✅ Access attempts logged for monitoring

▶️ How to Run the Project

Clone the repository

git clone https://github.com/gurusathvik01/hybrid-cloud-security-django


Install dependencies

pip install django


Apply migrations

python manage.py migrate


Run the server

python manage.py runserver

📚 What This Project Demonstrates (For Recruiters)

Strong understanding of Django backend development

Practical knowledge of security best practices

Experience with Git & GitHub workflows

Clean project structuring and documentation

Ability to build production-style web applications

👤 Author

Guru Sathvik
GitHub: https://github.com/gurusathvik01

This project was fully designed and implemented as an individual work for academic and skill-development purposes.

⭐ Why This Matters

This project reflects industry-relevant skills in:

Backend development

Secure system design

Cloud & hybrid architecture concepts

Ideal for roles such as:

Backend Developer

Django Developer

Cloud / Security Intern