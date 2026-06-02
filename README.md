# 🏦 Core Banking & Financial Security Suite (Digital Bank of India)

Welcome to the full-stack repository for the **Digital Bank of India** — a next-generation Core Banking System and security operations suite. 

This repository contains two main services that form a highly robust, secure, and compliant financial ecosystem:
1. **🏦 Core Banking Backend REST API:** Node.js, Express, and serverless Neon PostgreSQL, hardened with Redis-backed rate limiters, replay attack prevention, and symmetric AES-256 payload encryption.
2. **💻 Premium Staff & Customer Portal:** A sleek React 19 + Vite 8 frontend client featuring a curated dark theme, micro-interactions, role-restricted dashboard paths, and real-time bank officer queues.

---

## 🔗 Live Deployments

* **💻 Client Portal (Frontend):** [https://bank-management-system-19dp.onrender.com/](https://bank-management-system-19dp.onrender.com/)
* **🏦 Banking REST API (Backend):** [https://bank-management-system-backend-five.vercel.app/api](https://bank-management-system-backend-five.vercel.app/api)

---

## 📂 Repository Structure

* [**`/backend`**](./backend/README.md) - Contains the Node/Express backend code, cryptographic key handlers, PostgreSQL initializers, security middlewares, and automated audit loggers.
* [**`/frontend`**](./frontend/README.md) - Contains the React client application, Vite config schemas, context layers, custom page templates, and assets.

---

## ⚙️ Quick Local Architecture Setup

To run the full-stack system locally:

1. **Start the API Server:**
   * Go to `/backend`
   * Configure `.env` with PostgreSQL and Redis connections (details in [backend/README.md](./backend/README.md))
   * Run `npm install`
   * Initialize tables and seed master keys: `node db/init-full-db.js && node db/seed-admin.js`
   * Run the API server: `npm run dev` (running on `http://localhost:5000`)

2. **Start the Client Portal:**
   * Go to `/frontend`
   * Configure `.env` with `VITE_API_URL=http://localhost:5000/api` (details in [frontend/README.md](./frontend/README.md))
   * Run `npm install`
   * Launch the dev server: `npm run dev` (running on `http://localhost:5173`)

---

## 🛡️ Key Features & Cryptographic Hardening

* **Multi-Dashboard Operational Framework:** Custom portals tailored for **Customers**, **Tellers**, **Branch Managers**, **Compliance/KYC Officers**, and **Auditors**.
* **Zero-Trust Middlewares:** Dynamic Redis rate-limiting (100req/min) and request expiry validation protecting the ledger from replay attempts.
* **Master Key Bootstrapping:** AES-256-CBC and HMAC signature verification ensure every client request is mathematically verified.
* **Immutable Audit Trail:** Automated auditing triggers recording every action into the audit explorer database automatically.
