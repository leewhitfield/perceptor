import json
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import os
from pathlib import Path

from .mcp_server import PerceptorMcpServer
from .tenants import TenantManager

logger = logging.getLogger(__name__)

class MCPHttpHandler(BaseHTTPRequestHandler):
    def _send_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Perceptor-Tenant")

    def do_OPTIONS(self):
        self.send_response(200)
        self._send_cors_headers()
        self.end_headers()

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self._send_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
        else:
            self.send_error(404, "Not Found")

    def _get_server_for_request(self) -> PerceptorMcpServer | None:
        if not self.server.tenant_mode:
            return self.server.mcp_server

        auth_header = self.headers.get("Authorization", "")
        token = auth_header.removeprefix("Bearer ").strip()
        
        if not token:
            return None
            
        tenant = self.server.tenant_manager.resolve_from_token(token)
        if not tenant or not tenant.enabled:
            return None

        if tenant.id not in self.server.tenant_servers:
            # Important: OpenSearch config reads from env currently, so we set it per-tenant
            # in a multi-tenant single-process model this can be racy if not careful,
            # but for this MVP we rely on the MCP server creating a new instance.
            os.environ["FORENSIC_OPENSEARCH_INDEX"] = tenant.opensearch_index
            self.server.tenant_servers[tenant.id] = PerceptorMcpServer(
                root=Path(tenant.workspace_root),
                auth_token=tenant.mcp_token,
                allow_processing=self.server.mcp_server.allow_processing,
                allow_sensitive=self.server.mcp_server.allow_sensitive,
                allow_external_ai=self.server.mcp_server.allow_external_ai,
                plugin_paths=self.server.mcp_server.plugin_paths,
            )
        return self.server.tenant_servers[tenant.id]

    def do_POST(self):
        if self.path in ("/mcp", "/mcp/", "/"):
            server = self._get_server_for_request()
            if not server:
                self.send_error(401, "Unauthorized")
                return

            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8')
            try:
                request = json.loads(body)
                response = server.handle_message(request)
                if response:
                    response_bytes = json.dumps(response).encode('utf-8')
                    self.send_response(200)
                    self._send_cors_headers()
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(response_bytes)))
                    self.end_headers()
                    self.wfile.write(response_bytes)
                else:
                    self.send_response(204)
                    self._send_cors_headers()
                    self.end_headers()
            except json.JSONDecodeError:
                self.send_error(400, "Invalid JSON")
            except Exception as e:
                logger.error(f"Error handling MCP request: {e}")
                self.send_error(500, "Internal Server Error")
        else:
            self.send_error(404, "Not Found")

def run_mcp_http_server(
    mcp_server: PerceptorMcpServer,
    host: str = "0.0.0.0",
    port: int = 8080,
    tenant_mode: bool = False,
    root: Path | None = None
) -> int:
    class MCPServer(HTTPServer):
        def __init__(self, server_address, RequestHandlerClass, mcp_server):
            super().__init__(server_address, RequestHandlerClass)
            self.mcp_server = mcp_server
            self.tenant_mode = tenant_mode
            if self.tenant_mode and root:
                self.tenant_manager = TenantManager(root)
                self.tenant_servers = {}

    try:
        httpd = MCPServer((host, port), MCPHttpHandler, mcp_server)
        print(f"Starting MCP HTTP server on {host}:{port} (Tenant mode: {tenant_mode})")
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        return 0
    except Exception as e:
        print(f"Error starting server: {e}", file=sys.stderr)
        return 1
    return 0
