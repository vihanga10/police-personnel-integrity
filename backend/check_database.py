from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from database import create_identity_engine
from settings import Settings


def main() -> int:
    try:
        settings = Settings()
    except ValidationError:
        print("Configuration check failed. Check your local .env settings.")
        return 1

    engine = create_identity_engine(settings)

    try:
        with engine.connect() as connection:
            row = connection.execute(
                text(
                    "SELECT current_database() AS database_name, "
                    "current_user AS username, "
                    "1 AS connection_test"
                )
            ).mappings().one()

        if (
            row["database_name"] != "police_identity"
            or row["username"] != "police_identity_app"
            or row["connection_test"] != 1
        ):
            print("Database check failed: unexpected database or account.")
            return 1

        print("Database connection: OK")
        print("Database: police_identity")
        print("Account: police_identity_app")
        print("SELECT 1: PASSED")
        return 0

    except SQLAlchemyError:
        print("Database connection failed. Check the service and local settings.")
        return 1
    finally:
        engine.dispose()


if __name__ == "__main__":
    raise SystemExit(main())