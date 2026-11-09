"""Runtime settings, read from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Settings:
    data_dir: Path = field(
        default_factory=lambda: Path(os.getenv("AGENTPASS_DATA_DIR", PROJECT_ROOT / ".data"))
    )
    policy_file: Path = field(
        default_factory=lambda: Path(
            os.getenv("AGENTPASS_POLICY_FILE", PROJECT_ROOT / "config" / "policies.yaml")
        )
    )
    # The admin key stands in for the human user's login in this MVP.
    admin_key: str = field(default_factory=lambda: os.getenv("AGENTPASS_ADMIN_KEY", "dev-admin-key"))
    issuer: str = "agentpass"
    token_audience: str = "agentpass-gateway"
    access_token_ttl_seconds: int = 300  # 5 minutes
    max_assertion_age_seconds: int = 120

    @property
    def db_path(self) -> Path:
        return self.data_dir / "agentpass.db"

    @property
    def issuer_key_path(self) -> Path:
        return self.data_dir / "issuer_ed25519.pem"
