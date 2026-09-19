# 🛡️ VibeGuard — Autonomous Security & Secret Auditor for AI Coders

![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
![Express.js](https://img.shields.io/badge/Express.js-000000?style=for-the-badge&logo=express&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-316192?style=for-the-badge&logo=postgresql&logoColor=white)
![Supabase](https://img.shields.io/badge/Supabase-3ECF8E?style=for-the-badge&logo=supabase&logoColor=white)
![Vercel](https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)
![Security-SQLi Protected](https://img.shields.io/badge/Security-SQLi%20Immune-red?style=for-the-badge&logo=securityscorecard&logoColor=white)
![DecodeLabs](https://img.shields.io/badge/DecodeLabs-Project%203-7928CA?style=for-the-badge)

VibeGuard is an automated DevSecOps static analysis auditor built specifically for developers building applications using modern AI coding tools (such as Cursor, GitHub Copilot, ChatGPT, Gemini, Windsurf, and Claude Code). It scans codebases to identify accidental exposures of production database passwords, private API tokens, and insecure dynamic SQL queries, persisting all security findings into an enterprise relational database.

---

## 🎯 DecodeLabs Project 3: The 4 Pillars Architecture

This project strictly adheres to the core criteria defined in the DecodeLabs Industrial Training Kit (Project 3: Database Integration & State Persistence):

### 1. Pillar 1: The Blueprint (Relational Schema Design)
- **Relational Integrity**: Built on a normalized schema with a strict **One-to-Many (1:Many)** relationship[cite: 1]:
  - `repositories` (Parent Entity): Tracks repository metadata, aggregate health scores, and total findings count[cite: 1].
  - `findings` (Child Entity): Stores granular threat signatures linked via a Foreign Key (`repo_id`) with `ON DELETE CASCADE` referential integrity[cite: 1].
- **Schema-Level Constraints**: Enforces data integrity at the database layer using `NOT NULL`, `UNIQUE(repo_url)`, and strict `CHECK` constraints on health scores and threat severity levels[cite: 1].

### 2. Pillar 2: The Bridge (Persistent Database Integration)
- Eliminates temporary in-memory variable arrays in favor of durable **PostgreSQL (via Supabase)** cloud storage[cite: 1].
- Connects application code to database storage using the official `@supabase/supabase-js` bridge client[cite: 1].

### 3. Pillar 3: The Action (RESTful HTTP CRUD Operations)
- **CREATE (`POST /api/scan`)**: Ingests new target repositories or code snippets and commits findings into permanent storage (`INSERT`)[cite: 1].
- **READ (`GET /api/repos`)**: Fetches historical audit telemetry and associated relational findings (`SELECT`)[cite: 1].
- **UPDATE (`PATCH /api/findings/:id`)**: Mutates remediation statuses between `ACTIVE` and `MITIGATED` (`UPDATE`)[cite: 1].
- **DELETE (`DELETE /api/repos/:id`)**: Executes an atomic cascading purge of a repository and all its associated security findings (`DELETE`)[cite: 1].

### 4. Pillar 4: The Shield (SQL Injection Immunity & Defense)
- **Parameterized Execution**: Eliminates raw query string concatenation[cite: 1]. All user input and repository telemetry are processed as isolated, parameterized values, neutralizing SQL injection vectors (addressing the vulnerability showcased in Slides 13–14)[cite: 1].
- **Transport Hardening**: Incorporates `helmet.js` and strict CORS headers for API security.

---

## ✨ Core Features

- **Automated GitHub Tree Inspection**: Accepts a public GitHub URL, traverses the repository tree via GitHub REST APIs, and fetches relevant source code files without requiring manual file uploads.
- **Real-Time Streaming Terminal**: Employs Server-Sent Events (SSE) to display a live, file-by-file inspection log, giving immediate visibility into background scanning operations.
- **Precision Threat Signatures**:
  - OpenAI Secret API Keys (`sk-proj-...`)
  - Supabase & JWT Bearer Secret Tokens
  - AWS Access Keys & Identity Credentials
  - Production Database Connection Strings (PostgreSQL, MongoDB, MySQL)
  - Vulnerable String Concatenation SQL Injections[cite: 1]
  - Root perimeter checks (e.g., missing `.gitignore`)
- **Actionable Remediation Guidance**: Accompanies each finding with targeted code suggestions explaining how to refactor vulnerable patterns into secure production logic.
- **Modern Adaptive UI**: High-contrast, responsive interface supporting real-time Light and Dark mode toggles.

---

## 🛠️ Tech Stack

- **Runtime & Server**: Node.js, Express.js
- **Database**: PostgreSQL (Supabase Cloud)[cite: 1]
- **API Architecture**: RESTful CRUD with Server-Sent Events (SSE) streaming[cite: 1]
- **Security Protocols**: Parameterized SQL execution, Helmet.js, CORS[cite: 1]
- **Frontend**: Vanilla JavaScript (ES6+), CSS3 Variables, Semantic HTML5

---

## 🗄️ Database Schema Definition

```sql
-- Parent Table: Repositories[cite: 1]
CREATE TABLE repositories (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo_url TEXT NOT NULL UNIQUE,
    repo_name TEXT NOT NULL,
    default_branch TEXT DEFAULT 'main',
    health_score INT DEFAULT 100 CHECK (health_score BETWEEN 0 AND 100),
    total_findings INT DEFAULT 0 CHECK (total_findings >= 0),
    scanned_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Child Table: Findings (1:Many Relationship)[cite: 1]
CREATE TABLE findings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    repo_id UUID NOT NULL REFERENCES repositories(id) ON DELETE CASCADE,
    rule_id TEXT NOT NULL,
    secret_type TEXT NOT NULL,
    file_path TEXT NOT NULL,
    line_number INT NOT NULL CHECK (line_number > 0),
    masked_payload TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    suggestion TEXT,
    status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'MITIGATED', 'SUPPRESSED')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
🚀 Local Setup & Deployment
Clone the Repository:

Bash
git clone [https://github.com/Mohib565/VibeGuard.git](https://github.com/Mohib565/VibeGuard.git)
cd VibeGuard
Install Dependencies:

Bash
npm install
Configure Environment Variables:
Create a .env file in the root directory:

Code snippet
PORT=5000
SUPABASE_URL=YOUR_SUPABASE_PROJECT_URL
SUPABASE_SERVICE_KEY=YOUR_SUPABASE_SERVICE_ROLE_KEY
Launch the Engine:

Bash
npm start
Open http://localhost:5000 in your browser.

👨‍💻 Project Information
Developer: Syed Mohib Ali Shah

Course: DecodeLabs Industrial Training Program (Project 3 Milestone)[cite: 1]

Domain Focus: Full-Stack Web Development, DevSecOps & Database Persistence[cite: 1]



