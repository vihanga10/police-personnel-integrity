from logging.config import fileConfig

from alembic import context
from sqlalchemy import URL, create_engine, pool

import app.models  # noqa: F401
from app.db.base import Base
from migration_settings import MigrationSettings


config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_migration_url() -> URL:
    """Build the migration URL without storing credentials in alembic.ini."""

    settings = MigrationSettings()

    if settings.user != "police_identity_migrator":
        raise RuntimeError(
            "Alembic must use the police_identity_migrator account."
        )

    if settings.name != "police_identity":
        raise RuntimeError(
            "Alembic must target the police_identity database."
        )

    return URL.create(
        drivername="postgresql+psycopg",
        username=settings.user,
        password=settings.password.get_secret_value(),
        host=settings.host,
        port=settings.port,
        database=settings.name,
    )


def include_object(
    object_,
    name,
    type_,
    reflected,
    compare_to,
) -> bool:
    """Restrict generated migrations to the identity schema."""

    if type_ == "table":
        return object_.schema == "identity"

    return True


def run_migrations_offline() -> None:
    """Generate SQL without opening a database connection."""

    context.configure(
        url=get_migration_url(),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        include_schemas=True,
        include_object=include_object,
        version_table="alembic_version",
        version_table_schema="identity",
        compare_type=True,
        transaction_per_migration=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations using the restricted migration account."""

    connectable = create_engine(
        get_migration_url(),
        poolclass=pool.NullPool,
        hide_parameters=True,
    )

    try:
        with connectable.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                include_schemas=True,
                include_object=include_object,
                version_table="alembic_version",
                version_table_schema="identity",
                compare_type=True,
                transaction_per_migration=True,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        connectable.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()