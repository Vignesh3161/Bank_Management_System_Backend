# Bank_Management_System_Backend
An enterprise-grade Core Banking System (CBS) backend built with Node.js, Express, PostgreSQL, and Redis. Features include double-entry ledger accounting, AES-256 &amp; RSA-2048 security, AML/KYC compliance workflows, RBAC, fraud detection, immutable audit logging, and high-integrity financial transaction processing.
# Antigravity Core Banking API 🏦

[![Node.js](https://img.shields.io/badge/Node.js-20.x-green.svg)](https://nodejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15.x-blue.svg)](https://www.postgresql.org/)
[![Security](https://img.shields.io/badge/Security-AES--256%20|%20RSA-red.svg)](#security-architecture)

An enterprise-grade, high-security backend infrastructure for a modern Core Banking System (CBS). Built with architectural integrity, financial precision (Double-Entry Ledger), and regulatory compliance (AML/KYC) at its core.

---

## 🚀 Key Features

### 🔐 Security & Integrity
- **Military-Grade Encryption**: Balances and sensitive transaction data are encrypted at rest using **AES-256-CBC**.
- **Digital Fingerprints**: Transactions are signed with **RSA-2048** to ensure non-repudiation and prevent tampering.
- **Deduplication**: Uses **HMAC-SHA256** for email and mobile identifiers to prevent duplicate registrations without storing PII in plaintext.
- **Replay Protection**: Middleware to prevent request capturing and replay attacks.

### 💼 Financial Core
- **Double-Entry Ledger**: Every transaction generates balanced debit/credit entries in a dedicated ledger for 100% financial accuracy.
- **Multi-Role Access (RBAC)**:
  - `CUSTOMER`: Personal banking, transfers, and KYC submission.
  - `TELLER`: Cash deposits, withdrawals, and local transaction handling.
  - `BRANCH_MANAGER`: Operational oversight and limit approvals.
  - `KYC_OFFICER`: Document verification and identity vetting.
  - `AUDITOR`: Immutable trail review and regulatory reporting.
  - `SYSTEM_ADMIN`: Global configuration and staff management.

### 🛡️ Compliance & Fraud Prevention
- **KYC Workflow**: Automated document submission, OCR simulation, and manual review pipeline.
- **Audit Logging**: Immutable, gap-detecting audit trail with sequence-verified logging for all administrative actions.
- **Fraud Detection**: Real-time monitoring for velocity anomalies, structural patterns (AML), and geographical inconsistencies.
- **Interest Engine**: Automated accrual and credit system for FD and Savings accounts.

---

## 🛠️ Technology Stack
- **Runtime**: Node.js
- **Framework**: Express.js (V5)
- **Database**: PostgreSQL (Relational Data & ACID compliance)
- **Cache/Session**: Redis (Token blacklisting & Rate limiting)
- **Authentication**: JWT (JSON Web Tokens) with Token Versioning
- **Security Libraries**: `crypto`, `otplib` (2FA/TOTP), `bcryptjs`

---

## 📂 Project Structure
```text
backend/
├── controllers/    # Business logic for all 52 endpoints
├── db/             # PostgreSQL connection and helper queries
├── middleware/     # Auth, Audit, Security & Rate limiting
├── routes/         # Express route definitions
├── utils/          # Crypto helpers (AES, RSA, HMAC)
├── server.js       # Entry point & Middleware orchestration
├── schema.sql      # Database schema (DDL)
└── migrate.js      # Automation for schema deployment
```

---

## ⚙️ Setup & Installation

### 1. Prerequisites
- Node.js (v18+)
- PostgreSQL (v14+)
- Redis Server

### 2. Environment Configuration
Create a `.env` file in the root directory:
```env
PORT=5000
DATABASE_URL=postgresql://user:password@localhost:5432/banking_db
JWT_SECRET=your_super_secret_key_here
REDIS_URL=redis://localhost:6379
MASTER_KEY=32_byte_hex_for_aes_encryption
```

### 3. Installation
```bash
# Install dependencies
npm install

# Initialize database schema
node migrate.js

# Seed system administrator
node seed_admin.cjs
```

### 4. Running the Server
```bash
# Development mode (with nodemon)
npm run dev

# Production mode
npm start
```

---

## 📡 API Categories
| Category | Purpose |
| :--- | :--- |
| `/api/auth` | Login, 2FA, OTP Verification, Password Management |
| `/api/accounts` | Open accounts, Status management, Limits, Statements |
| `/api/transactions` | Transfers, Deposits, Withdrawals, Reversals |
| `/api/kyc` | Submission, Document handling, Approval pipeline |
| `/api/admin` | Branch config, Staff management, Global settings |
| `/api/audit` | Regulatory log access, System statistics |
| `/api/fraud` | Real-time alerts, Risk score resolution |

---

## 🔒 Security Architecture
The system employs a **Layered Defense Strategy**:
1. **Network Layer**: CORS restricted to trusted origins, Rate Limiting.
2. **Application Layer**: RBAC enforced on every route, Input validation.
3. **Data Layer**: Sensitive fields (Balance, Amount, Doc Paths) never stored in cleartext.
4. **Identity Layer**: 2FA required for high-value actions and staff logins.

---

## ⚖️ License
