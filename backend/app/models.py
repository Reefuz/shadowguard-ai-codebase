import re
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, ConfigDict, Field, field_validator

class Sensitivity(str, Enum):
    public="public"
    internal="internal"
    confidential="confidential"
    restricted="restricted"

class EventType(str, Enum):
    app_access="app_access"
    file_upload="file_upload"
    data_transfer="data_transfer"
    authentication="authentication"

class TelemetryEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    domain: str = Field(min_length=3, max_length=253)
    user_id: str = Field(min_length=2, max_length=80, pattern=r"^[A-Za-z0-9._@-]+$")
    department: str = Field(min_length=2, max_length=80)
    event_type: EventType
    data_sensitivity: Sensitivity = Sensitivity.public
    bytes_out: int = Field(default=0, ge=0, le=1000000000)
    occurred_at: datetime
    source: str = Field(default="unknown", min_length=2, max_length=60)

    @field_validator("domain")
    @classmethod
    def valid_domain(cls, value):
        value = value.lower().rstrip(".")
        if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", value):
            raise ValueError("domain must be a valid hostname")
        return value

class PolicyRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    vendor_name: str = Field(min_length=2, max_length=120)
    policy_text: str = Field(min_length=100, max_length=50000)

class RemediationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str = Field(min_length=5, max_length=300)
    approved_by: str = Field(min_length=2, max_length=80)
