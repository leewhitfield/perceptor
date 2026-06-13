import json
import secrets
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

@dataclass
class Tenant:
    id: str
    name: str
    workspace_root: str
    opensearch_index: str
    mcp_token: str
    created_at: str
    max_cases: int = 100
    max_evidence_gb: int = 500
    enabled: bool = True

class TenantManager:
    def __init__(self, root: Path):
        self.root = root
        self.tenants_file = self.root / "tenants.json"
        self._ensure_file()

    def _ensure_file(self):
        if not self.tenants_file.exists():
            self.tenants_file.parent.mkdir(parents=True, exist_ok=True)
            self.tenants_file.write_text("[]", encoding="utf-8")

    def _read_tenants(self) -> list[Tenant]:
        data = json.loads(self.tenants_file.read_text(encoding="utf-8"))
        return [Tenant(**t) for t in data]

    def _write_tenants(self, tenants: list[Tenant]):
        self.tenants_file.write_text(json.dumps([asdict(t) for t in tenants], indent=2), encoding="utf-8")

    def create_tenant(self, name: str) -> Tenant:
        tenant_id = str(uuid.uuid4())
        workspace_root = self.root / "tenants" / tenant_id
        workspace_root.mkdir(parents=True, exist_ok=True)
        
        tenant = Tenant(
            id=tenant_id,
            name=name,
            workspace_root=str(workspace_root),
            opensearch_index=f"forensic-content-{tenant_id}",
            mcp_token=secrets.token_hex(32),
            created_at=datetime.now(timezone.utc).isoformat()
        )
        
        tenants = self._read_tenants()
        tenants.append(tenant)
        self._write_tenants(tenants)
        return tenant

    def get_tenant(self, tenant_id: str) -> Tenant | None:
        for t in self._read_tenants():
            if t.id == tenant_id:
                return t
        return None

    def list_tenants(self) -> list[Tenant]:
        return self._read_tenants()

    def delete_tenant(self, tenant_id: str) -> None:
        tenants = self._read_tenants()
        tenants = [t for t in tenants if t.id != tenant_id]
        self._write_tenants(tenants)

    def resolve_from_token(self, token: str) -> Tenant | None:
        for t in self._read_tenants():
            if t.mcp_token == token:
                return t
        return None
