from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

NostrAction = Literal["login", "register", "link"]


class NostrChallengeIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    action: NostrAction = "login"
    redirect_to: Optional[str] = "/"


class NostrVerifyIn(BaseModel):
    model_config = ConfigDict(extra="ignore")

    k1: str = Field(min_length=64, max_length=64, description="32 bytes hex")
    event: dict[str, Any] = Field(
        description="Signed NIP-98 event (kind 27235) for this challenge"
    )
