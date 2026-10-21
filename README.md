# Bill Up

**A simple credit-ledger web app for small businesses.** Bill Up replaces the paper *khata* book: shop owners record what each customer owes, track due dates, and send payment reminders by email — automatically on the due date or with one click.

🔗 **Live demo:** [bill-up.onrender.com](https://bill-up.onrender.com)

> The live site runs on free hosting. If it has been idle, the first page load can take a few seconds.

---

## Table of contents

- [Features](#features)
- [Tech stack](#tech-stack)
- [Architecture](#architecture)
- [Project structure](#project-structure)
- [Getting started (local setup)](#getting-started-local-setup)
- [Configuration](#configuration)
- [Deployment](#deployment)
- [Security](#security)
- [Author](#author)

---

## Features

### For business owners
- **Business accounts** — register a business and log in with a personal User ID and password.
- **Customer management** — add, edit, search and delete customers, with their email and contact number.
- **Credit entries** — record each purchase with date, due date, amount, item details and notes; edit or delete entries later.
- **Outstanding totals** — see the amount each customer owes and the total outstanding across all customers.
- **Payment reminders**
  - **Email now** — send a formatted payment reminder to the customer instantly.
  - **Remind customer on due date** — email the customer automatically when the bill falls due.
  - **Remind me on due date** — email the owner a reminder to follow up.
  - Failed emails are retried every hour until they are delivered.

### For the administrator
- **Admin dashboard** — overview of all registered businesses, new sign-ups per month (chart), highest outstanding balances and scheduled reminders.
- **Account management** — remove a business together with all of its data.

### General
- Responsive interface that works on phones, tablets and desktops.
- Input validation on both the browser and the server, with clear error messages.

---

## Tech stack

| Layer | Technology | Purpose |
|---|---|---|
| **Language** | Python 3.13 | Application code |
| **Web framework** | [Flask](https://flask.palletsprojects.com/) 3 | Routing, sessions, templating |
| **Templates** | Jinja2 | Server-rendered HTML pages and emails |
| **Database** | [PostgreSQL](https://www.postgresql.org/) | Businesses, customers, entries and reminders |
| **ORM / DB toolkit** | SQLAlchemy 2, Flask-SQLAlchemy, psycopg2 | Database access and table management |
| **Forms & security** | Flask-WTF (CSRF protection), Werkzeug (password hashing) | Safe form handling and login |
| **Scheduling** | APScheduler (local) / external cron (production) | Due-date reminder runs |
| **Email** | Gmail SMTP (local) / [Brevo](https://www.brevo.com/) API (production) | Payment reminder emails |
| **Production server** | [Waitress](https://docs.pylonsproject.org/projects/waitress/) | WSGI server for the live site |
| **Frontend** | HTML5, CSS3, JavaScript, Bootstrap 4, Font Awesome, Chart.js | UI, icons and dashboard charts |
| **Configuration** | python-dotenv | Loads secrets from a `.env` file |

### Hosting (all free tier)

| Service | Role |
|---|---|
| [**Render**](https://render.com/) | Runs the Flask app and serves the site over HTTPS; redeploys on every push to `main` |
| [**Neon**](https://neon.tech/) | Managed PostgreSQL database in the cloud |
| [**Brevo**](https://www.brevo.com/) | Sends emails through an HTTPS API (Render's free plan blocks SMTP ports) |
| [**cron-job.org**](https://cron-job.org/) | Calls `/health` every 10 minutes to keep the app awake, and `/tasks/send-reminders` every hour to send due reminders |

---

## Architecture

```
            Browser (shop owner / admin)
                        │  HTTPS
                        ▼
              ┌───────────────────┐        SQL         ┌──────────────────┐
              │   Render          │ ─────────────────► │   Neon           │
              │   Flask + Waitress│                    │   PostgreSQL     │
              └───────────────────┘                    └──────────────────┘
                 ▲            │
   hourly / 10min│            │ HTTPS API
                 │            ▼
       ┌──────────────┐   ┌──────────────┐
       │ cron-job.org │   │    Brevo     │ ──► customer's inbox
       └──────────────┘   └──────────────┘
```

**Data model**
- `Registeration` — one row per business (login details are stored as password hashes).
- `<userid>_customers` — the customers of each business.
- `<userid>_<customer>` — the credit entries of each customer.
- `entry_reminders` — scheduled reminders waiting to be sent.

---

## Project structure

```
Bill-Up-Project-/
├── main.py                 # Flask app: routes, database, email, reminders, admin
├── requirements.txt        # Python dependencies (pinned versions)
├── render.yaml             # Render Blueprint (one-click deployment settings)
├── .env.example            # Template for the required settings — copy to .env
├── templates/
│   ├── index.html          # Landing page
│   ├── About.html
│   ├── login.html / register.html
│   ├── customer.html       # Customer list, search and totals
│   ├── account.html        # One customer's entries and reminders
│   ├── AdminLog.html / AdminDash.html
│   ├── emails/             # HTML email templates
│   └── partials/           # Shared navbar and footer
└── static/
    ├── css/                # Page styles
    ├── js/                 # csrf.js, confirm-dialog.js, scripts.js, vendor libraries
    └── img/
```

---

## Getting started (local setup)

### Prerequisites
- Python 3.13
- PostgreSQL 14 or newer
- A Gmail account with an [App Password](https://support.google.com/accounts/answer/185833) (or a Brevo API key)

### Steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/Divyansh2510/Bill-Up-Project-.git
   cd Bill-Up-Project-
   ```

2. **Create and activate a virtual environment**
   ```bash
   python -m venv .venv
   # Windows
   .venv\Scripts\activate
   # macOS / Linux
   source .venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create the database** in PostgreSQL (for example `Bill Up`).

5. **Configure the settings**
   ```bash
   cp .env.example .env
   ```
   Fill in `.env` (see [Configuration](#configuration)). Generate a secret key with:
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

6. **Run the app**
   ```bash
   python main.py
   ```
   Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Tables are created automatically on first start.

---

## Configuration

All secrets are read from environment variables (or a local `.env` file, which is git-ignored). See [`.env.example`](.env.example) for the full list.

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | Random string that signs login sessions |
| `DATABASE_URL` | ✅ | PostgreSQL connection string |
| `MAIL_USERNAME` | ✅ | Sender email address |
| `MAIL_PASSWORD` | Gmail only | Gmail App Password |
| `BREVO_API_KEY` | Optional | Send email through Brevo instead of Gmail |
| `MAIL_SENDER_NAME` | Optional | Display name on emails (default `Bill Up`) |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | ✅ | Admin dashboard login |
| `FLASK_DEBUG` | Optional | `true` for local development |
| `SESSION_COOKIE_SECURE` | Production | `true` when served over HTTPS |
| `TRUST_PROXY` | Production | `true` behind a hosting proxy (Render) |
| `RUN_SCHEDULER` | Optional | `false` when an external cron triggers reminders |
| `CRON_SECRET` | Production | Key required by `/tasks/send-reminders` |
| `TZ` | Optional | Time zone for due dates, e.g. `Asia/Kolkata` |

---

## Deployment

The repository includes a [`render.yaml`](render.yaml) Blueprint.

1. **Database** — create a free project on [Neon](https://neon.tech/) and copy its connection string.
2. **Email** — on [Brevo](https://www.brevo.com/), verify a sender address and create an API key.
3. **App** — on [Render](https://render.com/), choose **New → Blueprint**, select this repository and enter `DATABASE_URL`, `MAIL_USERNAME`, `BREVO_API_KEY`, `ADMIN_USERNAME` and `ADMIN_PASSWORD`. `SECRET_KEY` and `CRON_SECRET` are generated automatically.
4. **Scheduled jobs** — on [cron-job.org](https://cron-job.org/), create:
   - `GET /health` every 10 minutes (keeps the free instance awake)
   - `GET /tasks/send-reminders` every hour, with the header `X-Cron-Key: <CRON_SECRET>`

Every push to `main` redeploys the site automatically.

---

## Security

- Passwords are stored as salted hashes, never in plain text.
- All forms and in-page requests are protected against CSRF.
- Repeated failed logins are temporarily locked (5 attempts per 15 minutes).
- Session cookies are `HttpOnly`, `SameSite=Lax` and HTTPS-only in production.
- All user input is validated on the server; database queries are parameterised.
- Secrets live only in environment variables — nothing sensitive is committed to the repository.
- The reminder endpoint requires a secret key and returns `404` without it.

---

## Author

**Divyansh Jain** — [GitHub @Divyansh2510](https://github.com/Divyansh2510)

Issues and suggestions are welcome through [GitHub Issues](https://github.com/Divyansh2510/Bill-Up-Project-/issues).
