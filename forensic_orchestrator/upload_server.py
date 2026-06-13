import json
import logging
import os
import shutil
import uuid
import hashlib
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import sys

from .tenants import TenantManager

logger = logging.getLogger(__name__)

class UploadManager:
    def __init__(self, staging_dir: Path, evidence_dir: Path):
        self.staging_dir = staging_dir
        self.evidence_dir = evidence_dir
        self.staging_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.uploads = {}

    def _tenant_evidence_dir(self, tenant_id: str | None) -> Path:
        if tenant_id:
            tenant_dir = self.evidence_dir / tenant_id
            tenant_dir.mkdir(parents=True, exist_ok=True)
            return tenant_dir
        return self.evidence_dir

    def init_upload(self, tenant_id: str | None, filename: str, size_bytes: int) -> dict:
        upload_id = str(uuid.uuid4())
        staging_path = self.staging_dir / upload_id
        self.uploads[upload_id] = {
            "tenant_id": tenant_id,
            "filename": filename,
            "size_bytes": size_bytes,
            "staging_path": staging_path,
            "received_bytes": 0,
            "status": "uploading"
        }
        # Touch file
        staging_path.touch()
        return {"upload_id": upload_id, "status": "initialized"}

    def write_chunk(self, upload_id: str, offset: int, data: bytes) -> dict:
        if upload_id not in self.uploads:
            raise ValueError("Invalid upload_id")
        upload = self.uploads[upload_id]
        with open(upload["staging_path"], "r+b") as f:
            f.seek(offset)
            f.write(data)
        
        upload["received_bytes"] = max(upload["received_bytes"], offset + len(data))
        return {"upload_id": upload_id, "received_bytes": upload["received_bytes"]}

    def finalize(self, upload_id: str, expected_sha256: str | None = None) -> dict:
        if upload_id not in self.uploads:
            raise ValueError("Invalid upload_id")
        upload = self.uploads[upload_id]
        staging_path = upload["staging_path"]
        
        if expected_sha256:
            hasher = hashlib.sha256()
            with open(staging_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            if hasher.hexdigest() != expected_sha256:
                raise ValueError("SHA256 mismatch")
        
        target_dir = self._tenant_evidence_dir(upload["tenant_id"])
        target_path = target_dir / upload["filename"]
        shutil.move(str(staging_path), str(target_path))
        
        del self.uploads[upload_id]
        return {"status": "complete", "path": str(target_path)}

class UploadHttpHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _get_tenant(self):
        if not self.server.tenant_mode:
            return None
        auth_header = self.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return None
        tenant = self.server.tenant_manager.resolve_from_token(token)
        return tenant

    def _send_json(self, status: int, data: dict):
        self.send_response(status)
        self._send_cors_headers()
        self.send_header("Content-Type", "application/json")
        encoded = json.dumps(data).encode("utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_POST(self):
        if self.path == "/upload/init":
            tenant = self._get_tenant()
            if self.server.tenant_mode and not tenant:
                return self._send_json(401, {"error": "Unauthorized"})
            
            content_length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_length).decode("utf-8"))
            
            try:
                res = self.server.upload_manager.init_upload(
                    tenant.id if tenant else None,
                    body["filename"],
                    body.get("size_bytes", 0)
                )
                self._send_json(200, res)
            except Exception as e:
                self._send_json(500, {"error": str(e)})

        elif self.path.startswith("/upload/") and self.path.endswith("/finalize"):
            upload_id = self.path.split("/")[2]
            content_length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(content_length).decode("utf-8")) if content_length > 0 else {}
            
            try:
                res = self.server.upload_manager.finalize(upload_id, body.get("sha256"))
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
        else:
            self._send_json(404, {"error": "Not Found"})

    def do_PUT(self):
        if self.path.startswith("/upload/") and "/chunk/" in self.path:
            parts = self.path.split("/")
            upload_id = parts[2]
            offset = int(parts[4])
            
            content_length = int(self.headers.get("Content-Length", 0))
            data = self.rfile.read(content_length)
            
            try:
                res = self.server.upload_manager.write_chunk(upload_id, offset, data)
                self._send_json(200, res)
            except Exception as e:
                self._send_json(400, {"error": str(e)})
        else:
            self._send_json(404, {"error": "Not Found"})

def run_upload_server(
    host: str = "0.0.0.0",
    port: int = 8081,
    staging_dir: Path | None = None,
    evidence_dir: Path | None = None,
    tenant_mode: bool = False,
    root: Path | None = None
) -> int:
    class UploadHTTPServer(HTTPServer):
        def __init__(self, server_address, RequestHandlerClass):
            super().__init__(server_address, RequestHandlerClass)
            self.tenant_mode = tenant_mode
            self.upload_manager = UploadManager(
                staging_dir or Path("/tmp/perceptor-uploads"),
                evidence_dir or Path("/evidence")
            )
            if self.tenant_mode and root:
                self.tenant_manager = TenantManager(root)

    try:
        httpd = UploadHTTPServer((host, port), UploadHttpHandler)
        print(f"Starting Upload HTTP server on {host}:{port} (Tenant mode: {tenant_mode})")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        return 0
    except Exception as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        return 1
    return 0
