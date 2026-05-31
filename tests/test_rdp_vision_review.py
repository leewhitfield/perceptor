import csv
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from forensic_orchestrator.tools.rdp_vision_review import parse_rdp_vision_review_to_csv


def _rows(path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def _write_csv(path, fieldnames, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _seed_rdp_cache_outputs(tmp_path):
    parser_out = tmp_path / "out" / "RdpCacheParser"
    contact_sheet = parser_out / "contact_sheets" / "Jean_cache000.jpg"
    contact_sheet.parent.mkdir(parents=True)
    contact_sheet.write_bytes(b"fake jpeg bytes")
    _write_csv(
        parser_out / "RdpCacheItems.csv",
        ["record_type", "user_profile", "source_cache_path", "contact_sheet_path"],
        [
            {
                "record_type": "contact_sheet",
                "user_profile": "Jean",
                "source_cache_path": str(parser_out / "cache000.bin"),
                "contact_sheet_path": str(contact_sheet),
            }
        ],
    )
    (parser_out / "cache000.bin").write_bytes(b"cache")
    return parser_out, contact_sheet


def test_rdp_vision_review_falls_back_to_existing_tesseract_ocr(tmp_path, monkeypatch):
    parser_out, contact_sheet = _seed_rdp_cache_outputs(tmp_path)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    _write_csv(
        parser_out / "RdpVisualObservations.csv",
        [
            "user_profile",
            "source_cache_path",
            "contact_sheet_path",
            "observation_time_utc",
            "time_basis",
            "observation_type",
            "observed_application",
            "observed_text",
            "observed_path",
            "certainty",
            "caveat",
            "details_json",
        ],
        [
            {
                "user_profile": "Jean",
                "source_cache_path": str(parser_out / "cache000.bin"),
                "contact_sheet_path": str(contact_sheet),
                "observation_time_utc": "",
                "time_basis": "",
                "observation_type": "contact_sheet_ocr_text",
                "observed_application": "",
                "observed_text": "File Explorer C:\\Users\\Jean\\Documents",
                "observed_path": "",
                "certainty": "",
                "caveat": "",
                "details_json": "{}",
            }
        ],
    )

    outputs = parse_rdp_vision_review_to_csv(tmp_path / "unused", tmp_path / "out" / "RdpVisionReview")

    assert [path.name for path in outputs] == ["RdpVisualObservations.csv"]
    rows = _rows(outputs[0])
    assert rows[0]["observation_type"] == "tesseract_fallback_contact_sheet_ocr"
    assert rows[0]["observed_text"] == "File Explorer C:\\Users\\Jean\\Documents"
    details = json.loads(rows[0]["details_json"])
    assert details["provider"] == "tesseract_fallback"
    assert details["source_contact_sheet_sha256"]


def test_rdp_vision_review_uses_openai_api_without_storing_raw_review(tmp_path, monkeypatch):
    _seed_rdp_cache_outputs(tmp_path)
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            requests.append(json.loads(self.rfile.read(length).decode("utf-8")))
            body = {
                "id": "resp_test",
                "usage": {
                    "input_tokens": 1000,
                    "output_tokens": 200,
                    "total_tokens": 1200,
                    "input_tokens_details": {"cached_tokens": 100},
                },
                "output_text": json.dumps(
                    {
                        "summary": "Windows desktop with taskbar visible.",
                        "visible_applications": ["File Explorer"],
                        "visible_text": ["Documents"],
                        "visible_paths": ["C:\\Users\\Jean\\Documents"],
                        "notable_items": ["Explorer window fragment"],
                        "confidence": "medium",
                        "caveat": "Fragmented contact sheet.",
                    }
                ),
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode("utf-8"))

        def log_message(self, format, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("FORENSIC_ALLOW_EXTERNAL_AI", "1")
    monkeypatch.setenv("FORENSIC_OPENAI_RESPONSES_URL", f"http://127.0.0.1:{server.server_port}/v1/responses")
    try:
        outputs = parse_rdp_vision_review_to_csv(tmp_path / "unused", tmp_path / "out" / "RdpVisionReview")
    finally:
        server.shutdown()
        thread.join(timeout=5)

    rows = _rows(outputs[0])
    assert rows[0]["observation_type"] == "openai_vision_contact_sheet_review"
    assert rows[0]["observed_application"] == "File Explorer"
    assert rows[0]["observed_path"] == "C:\\Users\\Jean\\Documents"
    details = json.loads(rows[0]["details_json"])
    assert details["provider"] == "openai_api"
    assert details["response_id"] == "resp_test"
    assert details["openai_usage"]["input_tokens"] == 1000
    assert details["openai_usage"]["cached_input_tokens"] == 100
    assert details["openai_usage"]["output_tokens"] == 200
    assert details["openai_usage"]["total_tokens"] == 1200
    assert details["openai_usage"]["estimated_cost_usd"] > 0
    assert "raw_review" not in details
    assert requests[0]["input"][0]["content"][1]["type"] == "input_image"


def test_rdp_vision_review_requires_external_ai_opt_in(tmp_path, monkeypatch):
    _seed_rdp_cache_outputs(tmp_path)
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("FORENSIC_ALLOW_EXTERNAL_AI", raising=False)

    outputs = parse_rdp_vision_review_to_csv(tmp_path / "unused", tmp_path / "out" / "RdpVisionReview")

    rows = _rows(outputs[0])
    assert rows[0]["observation_type"] == "tesseract_fallback_no_text"
    details = json.loads(rows[0]["details_json"])
    assert details["fallback_reason"] == "OPENAI_API_KEY configured but FORENSIC_ALLOW_EXTERNAL_AI is not enabled"
