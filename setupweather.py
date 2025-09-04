"""
Database bootstrap script.

* Creates tables.
* Inserts default roles and users.
* Optionally loads a few sample countries.
"""
from sqlmodel import SQLModel, Session
from passlib.context import CryptContext

from main import engine, Role, User, Country

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def init_db() -> None:
    SQLModel.metadata.create_all(engine)

    with Session(engine) as session:
        # Roles
        admin_role = Role(id="admin", description="Administrator with full permissions")
        user_role = Role(id="user", description="Basic user with limited permissions")
        session.add_all([admin_role, user_role])

        # Users
        admin_user = User(
            id="admin",
            password=pwd_context.hash("admin123"),
            role_id="admin",
            disabled=False,
        )
        basic_user = User(
            id="user",
            password=pwd_context.hash("user123"),
            role_id="user",
            disabled=False,
        )
        session.add_all([admin_user, basic_user])

        # Sample countries
        italy = Country(id="ITA", name="Italy")
        usa = Country(id="USA", name="United States of America")
        session.add_all([italy, usa])

        session.commit()

    print("✅ Database initialized with roles, users, and sample countries.")


if __name__ == "__main__":
    init_db()
