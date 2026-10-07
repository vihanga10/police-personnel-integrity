from app.models.officer import Officer
from app.models.officer_address_version import OfficerAddressVersion
from app.models.officer_demographic_version import OfficerDemographicVersion
from app.models.officer_family_relation import OfficerFamilyRelation
from app.models.officer_name_version import OfficerNameVersion
from app.models.officer_physical_profile_version import (
    OfficerPhysicalProfileVersion,
)
from app.models.source_assertion import SourceAssertion
from app.models.source_system import SourceSystem
from app.models.officer_identifier_version import OfficerIdentifierVersion
from app.models.officer_contact_version import OfficerContactVersion
from app.models.officer_previous_employment_version import (
    OfficerPreviousEmploymentVersion,
)
from app.models.officer_restricted_profile_version import (
    OfficerRestrictedProfileVersion,
)
from app.models.officer_family_civil_event_version import (
    OfficerFamilyCivilEventVersion,
)
from app.models.officer_next_of_kin_version import OfficerNextOfKinVersion
from app.models.source_attestation import SourceAttestation

__all__ = [
    "Officer",
    "OfficerAddressVersion",
    "OfficerDemographicVersion",
    "OfficerFamilyRelation",
    "OfficerNameVersion",
    "OfficerPhysicalProfileVersion",
    "SourceAssertion",
    "SourceSystem",
    "OfficerIdentifierVersion",
    "OfficerContactVersion",
    "OfficerPreviousEmploymentVersion",
    "OfficerRestrictedProfileVersion",
    "OfficerFamilyCivilEventVersion",
    "OfficerNextOfKinVersion",
    "SourceAttestation",
]

from app.models.source_assertion_classification import (
    SourceAssertionClassification,
)

__all__.append("SourceAssertionClassification")

from app.models.profile_transform_receipt import ProfileTransformReceipt

__all__.append("ProfileTransformReceipt")

# Register cross-store preparation and receipt tables for Alembic discovery.
from app.models.service_delivery_storage import ServiceDeliveryPreparation, ServiceDeliveryCompletion

__all__.extend(["ServiceDeliveryPreparation", "ServiceDeliveryCompletion"])

# Register append-only historical delivery facts for Alembic discovery.
from app.models.history_delivery_storage import HistoryDeliveryPreparation, HistoryDeliveryCompletion

__all__.extend(["HistoryDeliveryPreparation", "HistoryDeliveryCompletion"])

# Register append-only SRB delivery facts for migration discovery.
from app.models.srb_delivery_storage import SrbDeliveryPreparation, SrbDeliveryCompletion

__all__.extend(["SrbDeliveryPreparation", "SrbDeliveryCompletion"])

# Register append-only SRB activity delivery facts for Alembic discovery.
from app.models.activity_delivery_storage import ActivityDeliveryPreparation, ActivityDeliveryCompletion

__all__.extend(["ActivityDeliveryPreparation", "ActivityDeliveryCompletion"])

# Register remaining encrypted source claims and append-only delivery receipts.
from app.models.remaining_delivery_storage import (RemainingSourceAssertion, RemainingDeliveryPreparation, RemainingDeliveryCompletion)
