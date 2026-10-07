"""Model/provenance preflight tests; actual SQL behavior needs the rollback checker."""
from uuid import uuid4
import pytest
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable
from app.db.base import Base
from app.db.staging_base import StagingBase
from app.models.service_delivery_storage import ServiceDeliveryCompletion, ServiceDeliveryPreparation
from app.identity.service_sql_ledger import ServiceSourceBinding


def test_completion_foreign_key_cannot_reference_another_preparation_digest():
    constraint = next(c for c in ServiceDeliveryCompletion.__table__.foreign_key_constraints
                      if c.name == "fk_service_completion_prepared_digest")
    assert [(e.parent.name, e.column.name) for e in constraint.elements] == [
        ("delivery_id", "delivery_id"), ("document_sha256", "document_sha256")]
    assert constraint.ondelete == "RESTRICT"


def test_preparation_foreign_keys_resolve_across_metadata_without_plaintext_fields():
    table = ServiceDeliveryPreparation.__table__
    assert table.fullname in StagingBase.metadata.tables
    assert table.fullname not in Base.metadata.tables
    targets = {fk.column.table.fullname for fk in table.foreign_keys}
    assert targets == {"staging.raw_record", "identity.officer", "identity.source_assertion", "identity.officer_identifier_version"}
    assert set(table.c.keys()).isdisjoint({"name", "nic", "current_rank", "current_unit", "service_status"})
    sql = str(CreateTable(table).compile(dialect=postgresql.dialect()))
    assert "encode(sha256(document_bson), 'hex')" in sql


@pytest.mark.parametrize("field,value", [
    ("raw_record_id", "BAD"), ("confirmation_sha256", "A" * 64),
    ("code_revision", "short"), ("identifier_version_id", "unverified-candidate"),
])
def test_malformed_source_bindings_rejected_before_sql(field, value):
    values = dict(raw_record_id="a" * 64, identifier_version_id=uuid4(), confirmation_sha256="b" * 64, code_revision="c" * 40)
    values[field] = value
    with pytest.raises(ValueError):
        ServiceSourceBinding(**values).validate()
