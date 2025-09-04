"""
Weather Report REST API (Lifespan‑ready)
---------------------------------------
Uses FastAPI's lifespan context instead of deprecated @app.on_event("startup").
"""

from datetime import datetime, timedelta, date, timezone
from typing import List, Optional
from contextlib import asynccontextmanager

import jwt
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from sqlmodel import (
    SQLModel, Field, Session, Relationship, create_engine, select
)

# ─────────────────────────── Configuration ────────────────────────────────
DATABASE_URL = "sqlite:///./weather.db"
SECRET_KEY = "change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

engine = create_engine(DATABASE_URL, echo=True, future=True)

# Configure lifespan to ensure DB schema exists
@asynccontextmanager
async def lifespan(app: FastAPI):
    SQLModel.metadata.create_all(engine)
    yield

app = FastAPI(
    title="Weather Report API",
    version="1.0.1",
    lifespan=lifespan,  # replaces deprecated startup event
)

# ───────────────────────────── Dependencies ───────────────────────────────
def get_db():
    """Provide a new SQLModel session per‑request."""
    with Session(engine) as session:
        yield session

# (rest of the file remains identical to previous version)
# For brevity, omitted here – reuse the existing code below this point.
# ───────────────────────────── Dependencies ───────────────────────────────
def get_db():
    """Provide a new SQLModel session per‑request."""
    with Session(engine) as session:
        yield session


# ───────────────────────── Authentication Models ──────────────────────────
class Role(SQLModel, table=True):
    """Application roles (admin / user)."""
    id: str = Field(primary_key=True)
    description: str


class User(SQLModel, table=True):
    """Registered users."""
    id: str = Field(primary_key=True)
    password: str
    role_id: str = Field(foreign_key="role.id")
    disabled: bool = False

    role: Role = Relationship()
    # Reverse relationships defined after City / Report definitions


# ───────────────────────────── Domain Models ──────────────────────────────
class Country(SQLModel, table=True):
    """Country entity (ISO‑like code as primary key)."""
    id: str = Field(primary_key=True, max_length=3)
    name: str

    cities: List["City"] = Relationship(back_populates="country")


class City(SQLModel, table=True):
    """City that can have multiple weather report histories."""
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    latitude: float
    longitude: float
    country_id: str = Field(foreign_key="country.id")
    created_by_id: str = Field(foreign_key="user.id")  # owner

    country: Country = Relationship(back_populates="cities")
    creator: User = Relationship(back_populates="cities")
    histories: List["WeatherHistory"] = Relationship(back_populates="city")


class Report(SQLModel, table=True):
    """Weather report definition (e.g., temperature, humidity...)."""
    id: Optional[int] = Field(default=None, primary_key=True)
    description: str  # human‑readable description (e.g., "Average temperature")
    unit: str          # measurement unit (e.g., "°C", "%", "mm")
    created_by_id: str = Field(foreign_key="user.id")  # owner

    creator: User = Relationship(back_populates="reports")
    histories: List["WeatherHistory"] = Relationship(back_populates="report")


class WeatherHistory(SQLModel, table=True):
    """Actual measured value of a report for a city in a date range."""
    id: Optional[int] = Field(default=None, primary_key=True)
    city_id: int = Field(foreign_key="city.id")
    report_id: int = Field(foreign_key="report.id")
    start_date: date
    end_date: date
    value: float

    city: City = Relationship(back_populates="histories")
    report: Report = Relationship(back_populates="histories")


# Define reverse relationships on User after classes exist
User.cities = Relationship(back_populates="creator")
User.reports = Relationship(back_populates="creator")


# ─────────────────────── Authentication utilities ─────────────────────────
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_user(db: Session, username: str) -> Optional[User]:
    """Return User by primary key or None."""
    return db.get(User, username)


def authenticate_user(db: Session, username: str, password: str) -> Optional[User]:
    user = get_user(db, username)
    if user and pwd_context.verify(password, user.password):
        return user
    return None


def create_access_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)
) -> User:
    creds_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if not username:
            raise creds_exc
    except jwt.PyJWTError:
        raise creds_exc
    user = get_user(db, username)
    if not user:
        raise creds_exc
    return user


async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


# ───────────────────────────── Permissions ────────────────────────────────
# Helper functions to enforce "admin OR owner" semantics on each entity.

# Country (admin‑only write)
def get_country(
    country_id: str,
    db: Session = Depends(get_db),
) -> Country:
    country = db.get(Country, country_id)
    if not country:
        raise HTTPException(status_code=404, detail="Country not found")
    return country


def require_admin(
    current_user: User = Depends(get_current_active_user),
) -> User:
    if current_user.role_id != "admin":
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return current_user


# City
def get_city(
    city_id: int,
    db: Session = Depends(get_db),
) -> City:
    city = db.get(City, city_id)
    if not city:
        raise HTTPException(status_code=404, detail="City not found")
    return city


def check_city_write(
    city: City = Depends(get_city),
    current_user: User = Depends(get_current_active_user),
) -> City:
    if current_user.role_id != "admin" and city.created_by_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return city


# Report
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
) -> Report:
    report = db.get(Report, report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


def check_report_write(
    report: Report = Depends(get_report),
    current_user: User = Depends(get_current_active_user),
) -> Report:
    if current_user.role_id != "admin" and report.created_by_id != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return report


# Weather history
def get_history(
    city_id: int,
    history_id: int,
    db: Session = Depends(get_db),
) -> WeatherHistory:
    history = db.get(WeatherHistory, history_id)
    if not history or history.city_id != city_id:
        raise HTTPException(status_code=404, detail="History not found")
    return history


def check_history_write(
    history: WeatherHistory = Depends(get_history),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
) -> WeatherHistory:
    """Only admin or the owner of the *associated city* can edit the history."""
    city_owner = db.get(City, history.city_id).created_by_id
    if current_user.role_id != "admin" and city_owner != current_user.id:
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return history


# ───────────────────────────── Auth endpoint ──────────────────────────────
@app.post("/token")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    access_token = create_access_token(
        data={"sub": user.id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
    )
    return {"access_token": access_token, "token_type": "bearer"}


# ─────────────────────────── Country endpoints ────────────────────────────
@app.post("/countries", response_model=Country)
def create_country(
    country: Country,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db.add(country)
    db.commit()
    db.refresh(country)
    return country


@app.get("/countries", response_model=List[Country])
def list_countries(db: Session = Depends(get_db)):
    return db.exec(select(Country)).all()


@app.get("/countries/{country_id}", response_model=Country)
def read_country(country: Country = Depends(get_country)):
    return country


@app.put("/countries/{country_id}", response_model=Country)
def update_country(
    country_id: str,
    data: Country,
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    country = db.get(Country, country_id)
    if not country:
        raise HTTPException(status_code=404, detail="Country not found")
    country.name = data.name
    db.add(country)
    db.commit()
    db.refresh(country)
    return country


@app.delete("/countries/{country_id}")
def delete_country(
    country: Country = Depends(get_country),
    admin: User = Depends(require_admin),
    db: Session = Depends(get_db),
):
    db.delete(country)
    db.commit()
    return {"detail": "Country deleted"}


# ───────────────────────────── City endpoints ─────────────────────────────
@app.post("/cities", response_model=City)
def create_city(
    city: City,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    city.created_by_id = current_user.id
    db.add(city)
    db.commit()
    db.refresh(city)
    return city


@app.get("/cities", response_model=List[City])
def list_cities(db: Session = Depends(get_db)):
    return db.exec(select(City)).all()


@app.get("/cities/{city_id}", response_model=City)
def read_city(city: City = Depends(get_city)):
    return city


@app.put("/cities/{city_id}", response_model=City)
def update_city(
    data: City,
    city: City = Depends(check_city_write),
    db: Session = Depends(get_db),
):
    city.name = data.name
    city.latitude = data.latitude
    city.longitude = data.longitude
    city.country_id = data.country_id
    db.add(city)
    db.commit()
    db.refresh(city)
    return city


@app.delete("/cities/{city_id}")
def delete_city(
    city: City = Depends(check_city_write),
    db: Session = Depends(get_db),
):
    db.delete(city)
    db.commit()
    return {"detail": "City deleted"}


# ─────────────────────────── Report endpoints ─────────────────────────────
@app.post("/reports", response_model=Report)
def create_report(
    report: Report,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
):
    report.created_by_id = current_user.id
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@app.get("/reports", response_model=List[Report])
def list_reports(db: Session = Depends(get_db)):
    return db.exec(select(Report)).all()


@app.get("/reports/{report_id}", response_model=Report)
def read_report(report: Report = Depends(get_report)):
    return report


@app.put("/reports/{report_id}", response_model=Report)
def update_report(
    data: Report,
    report: Report = Depends(check_report_write),
    db: Session = Depends(get_db),
):
    report.description = data.description
    report.unit = data.unit
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@app.delete("/reports/{report_id}")
def delete_report(
    report: Report = Depends(check_report_write),
    db: Session = Depends(get_db),
):
    db.delete(report)
    db.commit()
    return {"detail": "Report deleted"}


# ──────────────────────── Weather history endpoints ───────────────────────
@app.post("/cities/{city_id}/history", response_model=WeatherHistory)
def create_history(
    city_id: int,
    history: WeatherHistory,
    city: City = Depends(check_city_write),
    db: Session = Depends(get_db),
):
    history.city_id = city.id
    db.add(history)
    db.commit()
    db.refresh(history)
    return history


@app.get("/cities/{city_id}/history", response_model=List[WeatherHistory])
def list_history(city: City = Depends(get_city), db: Session = Depends(get_db)):
    return db.exec(
        select(WeatherHistory).where(WeatherHistory.city_id == city.id)
    ).all()


@app.get("/cities/{city_id}/history/{history_id}", response_model=WeatherHistory)
def read_history(history: WeatherHistory = Depends(get_history)):
    return history


@app.put("/cities/{city_id}/history/{history_id}", response_model=WeatherHistory)
def update_history(
    data: WeatherHistory,
    history: WeatherHistory = Depends(check_history_write),
    db: Session = Depends(get_db),
):
    history.start_date = data.start_date
    history.end_date = data.end_date
    history.value = data.value
    history.report_id = data.report_id
    db.add(history)
    db.commit()
    db.refresh(history)
    return history


@app.delete("/cities/{city_id}/history/{history_id}")
def delete_history(
    history: WeatherHistory = Depends(check_history_write),
    db: Session = Depends(get_db),
):
    db.delete(history)
    db.commit()
    return {"detail": "History deleted"}