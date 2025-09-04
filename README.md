# Weather Report REST API (FastAPI)

A robust, lifespan-ready **REST API** for managing weather data using **FastAPI** and **SQLModel**.  
This API supports authentication, role-based access, and CRUD operations for countries, cities, weather reports, and historical weather data.

---

## Features

- **User Authentication**: JWT-based login system with support for admin and regular users.
- **Role-Based Access**:
  - Admins: Full access to all resources.
  - Users: Limited access; can only manage their own cities, reports, and histories.
- **Entities**:
  - Countries (`Country`)
  - Cities (`City`)
  - Weather Reports (`Report`)
  - Historical Weather Data (`WeatherHistory`)
- **Modern FastAPI Lifespan**: Uses `lifespan` context instead of deprecated `@app.on_event("startup")`.
- **Database**: SQLite by default, powered by SQLModel (SQLAlchemy ORM under the hood). Easily replaceable with MySQL or PostgreSQL.
- **Secure Passwords**: Hashed with `bcrypt` via PassLib.
- **Interactive API Docs**: Auto-generated Swagger UI and ReDoc at `/docs` and `/redoc`.

---

## Installation

1. **Clone repository**:
```bash
git clone <your-repo-url>
cd fastapi-weather-api


2-Create virtual environment:
python -m venv venv
source venv/bin/activate  # Linux/macOS
venv\Scripts\activate     # Windows

3-Install dependencies:
python init_db.py

4-Initialize the database:
python init_db.py

5-Run the API server:
uvicorn main:app --reload

6-Open API documentation:

Swagger UI: http://127.0.0.1:8000/docs
ReDoc: http://127.0.0.1:8000/redoc

## Default users
| Username | Password | Role  |
| -------- | -------- | ----- |
| admin    | admin123 | Admin |
| user     | user123  | User  |

##Database Models Overview;
Role: Defines user roles (admin or user).
User: Registered users with hashed passwords.
Country: Countries with ISO-like IDs.
City: Cities linked to countries and users.
Report: Types of weather reports (temperature, humidity, etc.).
WeatherHistory: Historical data per city and report.


##Project Structure
fastapi-weather-api/
├─ main.py        # API endpoints and models
├─ init_db.py     # Bootstrap script for DB and default users
├─ requirements.txt
└─ README.md

