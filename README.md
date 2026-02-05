# Hybrid Cloud Security System (Django)

**Author:** Guru Sathvik  
**Role:** Full-Stack / Backend Developer  
**Focus Areas:** Cloud Security, Django, Secure File Systems

---

## Project Overview

The **Hybrid Cloud Security System** is a Django-based web application developed to demonstrate secure file handling, access control mechanisms, and audit logging in a hybrid cloud–like environment.

This project emphasizes **real-world security practices** such as authentication, encryption, access tracking, and environment-based secret management. It is designed to reflect production-level backend and cloud security concepts relevant to modern software systems.

---

## Key Objectives

- Implement secure user authentication with role-based access (Admin & User)
- Protect sensitive files using encryption and controlled access
- Maintain detailed audit logs for security monitoring
- Follow secure GitHub practices (no secrets committed)
- Simulate hybrid cloud storage behavior

---

## Features

- Role-based authentication (Admin / User)
- Secure file upload and access control
- Encryption utilities for sensitive data
- Access logging for auditing and monitoring
- Environment variable–based secret management
- Clean and secure GitHub repository structure

---

## Tech Stack

- **Backend:** Python, Django  
- **Frontend:** HTML, Django Templates  
- **Database:** SQLite  
- **Security:** Encryption utilities, access logging  
- **Version Control:** Git, GitHub  

---

## Project Structure

hybrid-cloud-security/
│
├── hybrid_cloud_security/ # Django project configuration
├── securityapp/ # Core application logic
│ ├── models.py # Database models
│ ├── views.py # Business logic
│ ├── utils/ # Security & utility modules
│ ├── templates/ # HTML templates
│ └── migrations/ # Database migrations
│
├── manage.py
├── .gitignore
└── README.md

---

## Security Notes

- Secret keys are **not stored** in the repository
- Sensitive files are excluded using `.gitignore`
- Environment variables are used for configuration
- Access attempts are logged for monitoring and auditing

---

## How to Run the Project

1. Clone the repository:
   ```bash
   git clone https://github.com/gurusathvik01/hybrid-cloud-security-django

2. Install dependencies:
pip install django
 
3. Apply database migrations:
python manage.py migrate

4. Start the development server:
python manage.py runserver

What This Project Demonstrates (For Recruiters)

Strong understanding of Django backend development

Practical application of security best practices

Experience with Git and GitHub workflows

Clean project structuring and documentation

Ability to build production-style web applications
Author

Guru Sathvik
GitHub: https://github.com/gurusathvik01

This project was independently designed and implemented for academic and skill-development purposes.

Why This Project Matters

This project showcases industry-relevant skills in:

Backend development

Secure system design

Cloud and hybrid architecture concepts

It is well-suited for roles such as:

Backend Developer

Django Developer

Cloud / Security Intern