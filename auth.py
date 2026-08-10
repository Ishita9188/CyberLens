import bcrypt
from sqlalchemy import text
from database import engine


def register_user(fullname, email, username, role, password):

    # Check whether email or username already exists
    with engine.connect() as connection:

        result = connection.execute(
            text("""
                SELECT id
                FROM users
                WHERE email = :email
                   OR username = :username
            """),
            {
                "email": email,
                "username": username
            }
        ).fetchone()

    if result:
        return False, "Email or username already exists."

    # Hash password
    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

    # Insert user
    with engine.begin() as connection:

        connection.execute(
            text("""
                INSERT INTO users
                (fullname, email, username, role, password)
                VALUES
                (:fullname, :email, :username, :role, :password)
            """),
            {
                "fullname": fullname,
                "email": email,
                "username": username,
                "role": role,
                "password": hashed_password
            }
        )

    return True, "Registration successful."


def authenticate_user(username, password):

    with engine.connect() as connection:

        user = connection.execute(
            text("""
                SELECT id, fullname, username, role, password
                FROM users
                WHERE username = :username
            """),
            {
                "username": username
            }
        ).fetchone()

    if not user:
        return None

    stored_password = user.password

    if bcrypt.checkpw(
        password.encode("utf-8"),
        stored_password.encode("utf-8")
    ):

        return {
            "id": user.id,
            "fullname": user.fullname,
            "username": user.username,
            "role": user.role
        }

    return None