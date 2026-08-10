import json
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")

DATABASE_URL = URL.create(
    drivername="postgresql+psycopg",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=int(DB_PORT),
    database=DB_NAME
)

engine = create_engine(DATABASE_URL)


def get_connection():
    return engine.connect()


def create_tables():
    with engine.begin() as connection:

        connection.execute(text("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                fullname VARCHAR(100) NOT NULL,
                email VARCHAR(150) UNIQUE NOT NULL,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """))

        connection.execute(text("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS role VARCHAR(100)
        """))


if __name__ == "__main__":
    try:
        create_tables()
        print("PostgreSQL connection successful.")
        print("Users table created/updated successfully.")
    except Exception as e:
        print("Database connection failed.")
        print("Error:", e)

import json
from sqlalchemy import text


def log_ner_analysis(user_id, input_text, entities):

    try:
        entity_count = len(entities)

        with engine.begin() as connection:

            connection.execute(
                text("""
                    INSERT INTO ner_analysis
                    (
                        user_id,
                        input_text,
                        entity_count,
                        entities
                    )
                    VALUES
                    (
                        :user_id,
                        :input_text,
                        :entity_count,
                        :entities
                    )
                """),
                {
                    "user_id": user_id,
                    "input_text": input_text,
                    "entity_count": entity_count,
                    "entities": json.dumps(entities)
                }
            )

        return True

    except Exception as e:

        print("NER logging error:", e)
        return False