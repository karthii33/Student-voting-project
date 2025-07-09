# 🗳️ Student Online Voting System - Flask + MongoDB

A secure and user-friendly online voting platform built with **Python Flask**, **MongoDB**, **Google OAuth**, and **Fernet encryption**. This project supports **admin control**, **predefined student login**, **encrypted vote storage**, and a modern animated UI.

## 🚀 Features

- 🧑‍🎓 Student login (with predefined users)
- 🔐 Google OAuth support
- 🔑 Encrypted vote storage using `cryptography.Fernet`
- 🧮 Real-time vote counting and admin dashboard
- ✅ Admin-only routes and candidate management
- 💅 Stylish animated vote page with responsive UI
- 📦 MongoDB as backend database

---

## 🛠️ Tech Stack

| Tech            | Purpose                     |
|-----------------|-----------------------------|
| Flask           | Backend framework (Python)  |
| MongoDB         | NoSQL database               |
| Flask-Dance     | Google OAuth integration     |
| Bcrypt          | Password hashing             |
| Fernet (Crypto) | Vote encryption              |
| HTML/CSS        | Frontend + Animations        |
| Font Awesome    | Icons and visuals            |

---

## 📂 Project Structure
/voting-app
│
├── templates/
│ ├── login.html
│ ├── vote.html
│ ├── result.html
│ ├── thanks.html
│ └── admin.html
│
├── static/ # Optional static folder
│
├── app.py # Main Flask server
├── requirements.txt
└── README.md


