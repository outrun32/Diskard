"""Runtime identity used by the investment-stand examples and console."""

from __future__ import annotations

from pydantic import BaseModel, Field


class Actor(BaseModel):
    cus: str
    api_key: str
    access_token: str | None = Field(default=None, repr=False)
