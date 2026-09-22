from sqlalchemy import URL, Engine, create_engine

from settings import Settings


def create_identity_engine(settings: Settings) -> Engine:
    connection_url = URL.create(
        drivername="postgresql+psycopg",
        username=settings.user,
        password=settings.password.get_secret_value(),
        host=settings.host,
        port=settings.port,
        database=settings.name,
    )

    return create_engine(
        connection_url,
        pool_pre_ping=True,
        pool_size=2,
        max_overflow=0,
        pool_timeout=5,
        connect_args={"connect_timeout": 5},
        echo=False,
        hide_parameters=True,
    )