# APISCAN
# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# postman-to-swagger_improved.py
#
# Key improvements vs. original:
# - Fix: removed accidentally nested helper defs; no hidden duplicates
# - Fix: normalize paths (:id, {{var}}) and always start with "/" (no trailing slashes)
# - Fix: base URL extraction ensures scheme + host (e.g., https://api.example.com)
# - Fix: Postman response headers parsing (list -> detect content-type)
# - Fix: handles urlencoded & formdata bodies; better JSON detection in 'raw'
# - Fix: promote inline schemas to #/components/schemas with stable refs
# - Fix: deduplicate/auto-add missing path params; add header parameters (excl. Content-Type/Authorization)
# - Enhancement: basic type inference for query/header params and examples
# - Enhancement: uses package __version__ when available
# - Enhancement: optional --yaml-only / --json-only / both (default both)
# - Enhancement: consistent styled logging and exit codes
#
# Usage:
#   python postman-to-swagger_improved.py --postman collection.json --output openapi_output --both --open-ui --serve --zip
#
import argparse
import json
import webbrowser
import zipfile
from http.server import SimpleHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
import time
from urllib.parse import urlparse
from typing import Dict, List, Optional, Tuple, Any
import re
import sys

try:
    from version import __version__ as PKG_VERSION
except Exception:
    PKG_VERSION = "1.0.0"

HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}
# ---------- pretty console ----------
def styled_print(message: str, status: str = "info"):
    symbols = {
        "info": "[i]",
        "ok": "[V]",
        "warn": "[!]",
        "fail": "[X]",
        "run": "[->]",
    }
    colors = {
        "info": "\033[94m",
        "ok": "\033[92m",
        "warn": "\033[93m",
        "fail": "\033[91m",
        "run": "\033[96m",
    }
    reset = "\033[0m"
    print(f"{colors.get(status, '')}{symbols.get(status, '')} {message}{reset}")

# ---------- helpers ----------
def replace_invalid_characters(text):
    # Optionally normalize strings for OpenAPI compatibility
    if not isinstance(text, str):
        return text
    return re.sub(r"[^\w\-\.\:\/\{\}\[\] ]+", "", text)

def dedupe_parameters(params, context):
    seen = set()
    out = []
    dups = []
    for p in params or []:
        name = (p.get("name") or "").strip()
        loc = (p.get("in") or "").strip()
        key = (loc, name.lower() if loc == "header" else name)
        if key in seen:
            dups.append(name)
            continue
        seen.add(key)
        out.append(p)
    if dups:
        print(f"[!] Warning: Duplicate parameters {dups} removed from {context}")
    return out

def process_openapi(doc):
    paths = doc.get("paths", {})
    for path, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue

        if "parameters" in path_item:
            path_item["parameters"] = dedupe_parameters(path_item["parameters"], f"PATH {path}")

        for method, op in path_item.items():
            if method.lower() not in HTTP_METHODS:
                continue
            if not isinstance(op, dict):
                continue
            if "parameters" in op:
                op["parameters"] = dedupe_parameters(op["parameters"], f"{method.upper()} {path}")

    return doc

def _infer_type(value: str) -> str:
    # try to infer JSON Schema types from string examples
    if value is None:
        return "string"
    v = str(value).strip().lower()
    if v in {"true","false"}:
        return "boolean"
    try:
        int(v)
        return "integer"
    except Exception:
        pass
    try:
        float(v)
        return "number"
    except Exception:
        pass
    return "string"

def _parse_bool(value: str) -> bool | None:
    if value is None:
        return None
    v = str(value).strip().lower()
    if v in {"true","1","yes","y"}:
        return True
    if v in {"false","0","no","n"}:
        return False
    return None

def _detect_content_type_from_headers(headers: list) -> str:
    if not isinstance(headers, list):
        return "application/json"
    for h in headers:
        key = str(h.get("key","")).lower()
        if key == "content-type":
            return h.get("value","application/json") or "application/json"
    return "application/json"

def _store_schema(schema: dict, components: dict) -> str:
    import hashlib
    schema_str = json.dumps(schema, sort_keys=True).encode("utf-8")
    ref_name = "Schema_" + hashlib.sha1(schema_str).hexdigest()[:10]
    components.setdefault("schemas", {})
    if ref_name not in components["schemas"]:
        components["schemas"][ref_name] = schema
    return ref_name

def enrich_description(summary: str, existing: str = "") -> str:
    if existing and existing.strip().lower() != "no description available":
        return existing
    return f"This endpoint handles the action: '{summary}'. More details to be documented."

def apply_descriptions_to_operations(paths: dict) -> None:
    for path, methods in paths.items():
        for method, op in methods.items():
            if not isinstance(op, dict):  # guard against non-objects
                continue
            summary = op.get("summary", "No summary")
            op["description"] = enrich_description(summary, op.get("description", ""))

def extract_inline_schemas(paths: dict, components: dict) -> None:
    for path_item in paths.values():
        for method in path_item.values():
            if not isinstance(method, dict):
                continue
            if "requestBody" in method:
                content = method["requestBody"].get("content", {})
                for _, media_def in content.items():
                    schema = media_def.get("schema")
                    if schema and isinstance(schema, dict):
                        ref_name = _store_schema(schema, components)
                        media_def["schema"] = {"$ref": f"#/components/schemas/{ref_name}"}
            for resp in method.get("responses", {}).values():
                content = resp.get("content", {})
                for _, media_def in content.items():
                    schema = media_def.get("schema")
                    if schema and isinstance(schema, dict):
                        ref_name = _store_schema(schema, components)
                        media_def["schema"] = {"$ref": f"#/components/schemas/{ref_name}"}

def normalize_tags(paths: dict) -> None:
    for path_item in paths.values():
        for method in path_item.values():
            if not isinstance(method, dict):
                continue
            tags = method.get("tags", [])
            if tags:
                method["tags"] = [t.replace(" ", "_").replace("/", "_")[:40] for t in tags]
            else:
                method["tags"] = ["default"]

def enhance_swagger(swagger_data: dict) -> dict:
    paths = swagger_data.get("paths", {})
    components = swagger_data.setdefault("components", {})
    apply_descriptions_to_operations(paths)
    extract_inline_schemas(paths, components)
    normalize_tags(paths)
    return swagger_data

# ---------- main builder ----------
class EnhancedSwaggerBuilder:
    def __init__(self, postman_path: str):
        self.postman_path = Path(postman_path)
        self.postman_data = self._load_postman()
        self.operation_ids = set()
        self.path_counter = {}
        self.parameter_tracker = {}
        self.server_variables = {}
        self.environment_data = None
        
    def load_environment_json(self, env_path: str):
        """Load a Postman environment JSON and store in self.environment_data."""
        if not env_path:
            return
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                self.environment_data = json.load(f)
            styled_print(f"[->] Loaded Postman environment: {env_path}", "info")
        except Exception as e:
            styled_print(f"[!] Failed to load environment: {e}", "fail")
            self.environment_data = None


    def _generate_unique_operation_id(self, name: str) -> str:
        base_id = re.sub(r"[^a-zA-Z0-9_]", "_", name.lower())
        if base_id not in self.operation_ids:
            self.operation_ids.add(base_id)
            return base_id
        counter = 1
        while f"{base_id}_{counter}" in self.operation_ids:
            counter += 1
        unique_id = f"{base_id}_{counter}"
        self.operation_ids.add(unique_id)
        return unique_id

    def _load_postman(self) -> dict:
        if not self.postman_path.exists():
            raise FileNotFoundError(f"File not found: {self.postman_path}")
        with open(self.postman_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "info" not in data or "item" not in data:
            raise ValueError("Invalid Postman structure (missing 'info' or 'item')")
        return data

    @staticmethod
    def _normalize_path(path: str) -> str:
        # :id -> {id}; {{var}} -> {var}; ensure leading "/" and remove trailing "/"
        path = re.sub(r":(\w+)", r"{\1}", path)
        path = re.sub(r"{{(.*?)}}", r"{\1}", path)
        if not path.startswith("/"):
            path = "/" + path
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        return path

    def _get_base_url(self) -> str:
        # 1) variable baseUrl if present
        variables = self.postman_data.get("variable", [])
        base_url = next((v.get("value") for v in variables if v.get("key") == "baseUrl"), "")

        # 2) Try first request
        if not base_url:
            first_request = self._find_first_request(self.postman_data.get("item", []))
            if first_request:
                url = first_request.get("request", {}).get("url")
                if isinstance(url, dict):
                    scheme = url.get("protocol", "https")
                    host = ".".join(url.get("host", [])) or ""
                    base_url = f"{scheme}://{host}" if host else ""
                elif isinstance(url, str):
                    parsed = urlparse(url)
                    scheme = parsed.scheme or "https"
                    host = parsed.netloc or ""
                    base_url = f"{scheme}://{host}" if host else ""

        # 3) Replace Postman {{vars}} to OpenAPI {vars}
        base_url = base_url.rstrip("/")
        placeholders = re.findall(r"{{(.*?)}}", base_url)
        if placeholders:
            for name in placeholders:
                base_url = base_url.replace("{{"+name+"}}", "{"+name+"}")
            self.server_variables = {
                name: {
                    "default": f"example.{name}.com",
                    "description": f"Variable '{name}' automatically generated"
                } for name in placeholders
            }
        elif base_url:
            self.server_variables = {
                "baseUrl": {
                    "default": base_url,
                    "description": "Base server URL"
                }
            }
        else:
            base_url = "https://api.example.com"
            self.server_variables = {
                "baseUrl": {
                    "default": base_url,
                    "description": "Default fallback URL"
                }
            }
        return base_url

    def convert_to_swagger(self) -> dict:
        """
        Build an OpenAPI 3.0 document from the loaded Postman collection.

        - Uses self._get_base_url() to determine the primary server URL.
        - Adds server variables ONLY when the server URL actually contains {placeholders}.
        - If a Postman environment is loaded (self.environment_data), use its values
          as defaults for matching server variables.
        - Extracts securitySchemes and global security defaults.
        - Fills paths via self._process_items().
        """
        base_url = self._get_base_url()

        # Server-object opbouwen; variables alleen toevoegen als er placeholders in de URL zitten.
        server_obj = {"url": base_url}
        try:
            has_placeholders = bool(re.search(r"{[^}]+}", base_url))
        except Exception:
            has_placeholders = False

        if has_placeholders and self.server_variables:
            # Defaults vullen vanuit Postman environment (alleen enabled waarden)
            if getattr(self, "environment_data", None):
                try:
                    env_values = {
                        str(v.get("key")): v.get("value")
                        for v in self.environment_data.get("values", [])
                        if v.get("enabled", True) and v.get("key")
                    }
                except Exception:
                    env_values = {}
                # Koppel env defaults aan gelijknamige server-variables
                for var_name in list(self.server_variables.keys()):
                    if var_name in env_values and env_values[var_name] not in (None, ""):
                        self.server_variables[var_name]["default"] = env_values[var_name]

            server_obj["variables"] = self.server_variables

        # Info/description veilig uit Postman trekken
        info_obj = self.postman_data.get("info", {}) or {}
        desc = info_obj.get("description", "")
        if isinstance(desc, dict):  # sommige exports hebben object i.p.v. string
            desc = desc.get("content", "") or ""

        swagger = {
            "openapi": "3.0.0",
            "info": {
                "title": info_obj.get("name", "Converted from Postman"),
                "version": PKG_VERSION,
                "description": desc,
                "contact": {
                    "name": "API Support",
                    "email": "support@example.com",
                    "url": "https://example.com/contact"
                }
            },
            "externalDocs": {
                "description": "Full documentation",
                "url": "https://example.com/docs"
            },
            "tags": [
                {"name": "default", "description": "General API endpoints"}
            ],
            "servers": [server_obj],
            "paths": {},
            "components": {
                "securitySchemes": self._extract_auth_schemes()
            },
            # Let op: root-level security geldt voor alle operations.
            "security": self._build_security_blocks()
        }

        # Paths vullen vanuit de Postman items
        self._process_items(self.postman_data.get("item", []), swagger["paths"])

        return swagger


    def _parse_url(self, url: Dict|str) -> Tuple[str, List[Dict]]:
        if isinstance(url, str):
            parsed = urlparse(url)
            path = parsed.path or "/unnamed_path"
            path = self._normalize_path(path)
            params = self._parse_query_string(parsed.query)
            path_params = self._extract_path_parameters(path)
            return path, path_params + params

        raw_path = "/" + "/".join(url.get("path", ["unnamed_path"]))
        path = self._normalize_path(raw_path)

        query_params = []
        for param in url.get("query", []):
            key = param.get("key")
            if not key or not isinstance(key, str):
                continue
            example = param.get("value")
            schema_type = _infer_type(example if example is not None else "")
            query_params.append({
                "name": str(key),
                "in": "query",
                "description": param.get("description", "") or "No description",
                "required": False,  # safer default
                "schema": {"type": schema_type},
                **({"example": example} if example is not None else {})
            })

        path_params = self._extract_path_parameters(path)
        return path, path_params + query_params

        
    def _extract_path_parameters(self, path: str) -> List[Dict]:
        return [
            {
                "name": name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": f"URL path parameter {name}"
            }
            for name in sorted(set(re.findall(r"{(.*?)}", path)))
        ]

    def _find_first_request(self, items):
        for item in items:
            if "item" in item:
                found = self._find_first_request(item["item"])
                if found:
                    return found
            elif "request" in item:
                return item
        return None

    def _extract_auth_schemes(self) -> Dict:
        return {
            "bearerAuth": {"type": "http", "scheme": "bearer", "bearerFormat": "JWT"},
            "basicAuth": {"type": "http", "scheme": "basic"},
            "apiKeyAuth": {"type": "apiKey", "in": "header", "name": "X-API-Key"},
            "clientCredentials": {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "https://example.com/oauth/token",
                        "scopes": {"read": "Read access", "write": "Write access"}
                    }
                }
            }
        }

    def _build_security_blocks(self) -> List[Dict]:
        return [
            {"bearerAuth": []},
            {"basicAuth": []},
            {"apiKeyAuth": []},
            {"clientCredentials": ["read", "write"]},
        ]

    def _process_items(self, items: List, paths: Dict, current_folder: str = "") -> None:
        for item in items:
            if "item" in item:  # folder
                self._process_items(item["item"], paths, current_folder=item.get("name",""))
            else:
                self._add_request_to_paths(item, paths, current_folder)

    def _add_request_to_paths(self, item: Dict, paths: Dict, current_folder: str = "") -> None:
        request = item.get("request", {})
        if not request:
            return

        method = request.get("method", "GET").lower()
        url = request.get("url")
        if not url:
            return

        path, parameters = self._parse_url(url)
        if not path or path == "/":
            path = "/unnamed_path"
            styled_print(f"Empty path found, replaced with {path}", "warn")

        # Track usage
        self.path_counter[path] = self.path_counter.get(path, 0) + 1

        if path not in paths:
            paths[path] = {}

        # header params (skip content-type, authorization, accept)
        header_params = []
        for h in request.get("header", []):
            k = str(h.get("key","")).strip()
            if not k:
                continue
            kl = k.lower()
            if kl in {"content-type", "authorization", "accept"}:
                continue
            example = h.get("value")
            header_params.append({
                "name": k,
                "in": "header",
                "required": False,
                "schema": {"type": _infer_type(example if example is not None else "")},
                **({"example": example} if example is not None else {})
            })

        # merge + validate
        parameters = self._validate_and_deduplicate_parameters(path, method, parameters + header_params)

        operation = {
            "summary": item.get("name", "Unnamed endpoint") or "Unnamed endpoint",
            "description": request.get("description", "") or "No description available",
            "parameters": parameters,
            "tags": [ (current_folder or item.get("name","default")).replace(" ", "_")[:40] ],
            "operationId": self._generate_unique_operation_id(item.get("name", f"{method}_{path}")),
            "responses": self._parse_responses(item, request)
        }

        if method != "get":
            body = self._parse_request_body(request)
            if body:
                operation["requestBody"] = body

        paths[path][method] = operation

        
        
    def _parse_query_string(self, query: str) -> List[Dict]:
        if not query:
            return []
        params = []
        for pair in query.split("&"):
            if "=" in pair:
                key, value = pair.split("=", 1)
                params.append({
                    "name": key,
                    "in": "query",
                    "schema": {"type": _infer_type(value)},
                    **({"example": value} if value != "" else {})
                })
        return params

    def _parse_request_body(self, request: Dict) -> Optional[Dict]:
        body = request.get("body")
        if not body:
            return None

        # content-type from headers, default json
        content_type = _detect_content_type_from_headers(request.get("header", []))

        mode = body.get("mode")
        if mode == "raw":
            raw = body.get("raw", "")
            # Try JSON first
            try:
                json_body = json.loads(raw) if isinstance(raw, str) else raw
                return {"content": {content_type: {"schema": self._json_to_schema(json_body)}}}
            except Exception:
                # keep as string example
                return {"content": {content_type: {"schema": {"type": "string"}, "example": raw}}}

        if mode == "urlencoded":
            props = {}
            required = []
            for f in body.get("urlencoded", []):
                key = f.get("key")
                if not key:
                    continue
                example = f.get("value")
                props[key] = {"type": _infer_type(example if example is not None else "")}
                if example is not None:
                    props[key]["example"] = example
                if not f.get("disabled", False):
                    required.append(key)
            schema = {"type": "object", "properties": props}
            if required:
                schema["required"] = required
            return {"content": {"application/x-www-form-urlencoded": {"schema": schema}}}

        if mode == "formdata":
            props = {}
            required = []
            for f in body.get("formdata", []):
                key = f.get("key")
                if not key:
                    continue
                example = f.get("value")
                props[key] = {"type": _infer_type(example if example is not None else "")}
                if example is not None:
                    props[key]["example"] = example
                if not f.get("disabled", False):
                    required.append(key)
            schema = {"type": "object", "properties": props}
            if required:
                schema["required"] = required
            return {"content": {"multipart/form-data": {"schema": schema}}}

        return None

    def _json_to_schema(self, data: Any) -> Dict:
        if isinstance(data, dict):
            properties = {}
            required = []
            for k, v in data.items():
                properties[k] = self._json_to_schema(v)
                if v is not None:
                    required.append(k)
            schema = {"type": "object", "properties": properties}
            if required:
                schema["required"] = required
            return schema
        elif isinstance(data, list):
            if data:
                return {"type": "array", "items": self._json_to_schema(data[0])}
            else:
                return {"type": "array", "items": {"type": "string", "description": "Example: empty list"}}
        else:
            py_type = type(data).__name__
            type_map = {"str": "string", "int": "integer", "float": "number", "bool": "boolean", "NoneType": "string"}
            return {"type": type_map.get(py_type, "string")}

    def _parse_responses(self, item: Dict, request: Dict) -> Dict:
        # defaults als fallback
        responses = {
            "200": {
                "description": "Successful operation",
                "content": {"application/json": {"example": {"status": "success"}}}
            },
            "400": {
                "description": "Invalid input",
                "content": {"application/json": {"example": {"error": "Invalid input"}}}
            },
            "500": {
                "description": "Server error",
                "content": {"application/json": {"example": {"error": "Internal server error"}}}
            }
        }

        # Postman v2.1 bewaart responses als sibling van request: item["response"] (list)
        examples = item.get("response", []) or []
        for example in examples:
            code = str(example.get("code", "200"))

            # Content-Type uit response headers bepalen
            headers = example.get("header", [])
            ctype = _detect_content_type_from_headers(headers)

            # Body kan string (JSON of plain text) of al dict/list zijn
            body = example.get("body")
            payload = None
            if isinstance(body, (dict, list)):
                payload = body
            elif isinstance(body, str):
                try:
                    payload = json.loads(body)
                except Exception:
                    payload = body  # plain text

            # Response entry aanmaken of aanvullen
            if code not in responses:
                responses[code] = {
                    "description": example.get("name", "Example response") or "No description",
                    "content": {}
                }

            # Schema + example invullen
            if isinstance(payload, (dict, list)):
                schema = self._json_to_schema(payload)
                responses[code].setdefault("content", {}).setdefault(ctype, {})["schema"] = schema
                responses[code]["content"][ctype]["example"] = payload
            else:
                responses[code].setdefault("content", {}).setdefault(ctype, {})["schema"] = {"type": "string"}
                responses[code]["content"][ctype]["example"] = payload

        return responses


    def _validate_and_deduplicate_parameters(self, path: str, method: str, parameters: List[Dict]) -> List[Dict]:
        unique_params = []
        seen_params = set()
        duplicates = []

        for param in parameters:
            pname = param.get("name")
            pin = param.get("in")
            if not pname or not pin:
                continue
            key = (pname.lower(), pin)
            if key in seen_params:
                duplicates.append(pname)
                continue
            seen_params.add(key)
            unique_params.append(param)

        if duplicates:
            styled_print(f"Warning: Duplicate parameters {duplicates} removed from {method.upper()} {path}", "warn")

        # ensure all path placeholders are defined
        url_placeholders = set(re.findall(r"{(.*?)}", path))
        defined = set(p["name"] for p in unique_params if p.get("in") == "path")
        missing = url_placeholders - defined
        for name in sorted(missing):
            unique_params.append({
                "name": name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": f"Auto-generated path parameter {name}"
            })
            styled_print(f"Warning: Missing path parameter '{name}' added to {method.upper()} {path}", "warn")

        return unique_params

# ---------- server & zip utils ----------
def serve_file(path: Path, port: int = 8000):
    class CustomHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass
    def start_server():
        httpd = HTTPServer(("localhost", port), CustomHandler)
        styled_print(f"Start tijdelijke webserver op http://localhost:{port}/", "info")
        webbrowser.open(f"http://localhost:{port}/{path.name}")
        httpd.serve_forever()
    threading.Thread(target=start_server, daemon=True).start()
    time.sleep(2)

def zip_output(swagger_path: Path) -> Path:
    zip_path = swagger_path.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, "w") as zipf:
        zipf.write(swagger_path, arcname=swagger_path.name)
        yaml_path = swagger_path.with_suffix(".yaml")
        if yaml_path.exists():
            zipf.write(yaml_path, arcname=yaml_path.name)
    return zip_path

# ---------- CLI ----------
def main():
    parser = argparse.ArgumentParser(description="Convert a Postman v2.1 collection to OpenAPI 3.0 Swagger (c) Perry Mertens 2025.")
    parser.add_argument("--postman", required=True, help="Path to Postman .json file")
    parser.add_argument("--output", default="openapi_output", help="Output file path WITHOUT extension (we add .json/.yaml)")
    parser.add_argument("--open-ui", action="store_true", help="Open Swagger JSON in default browser")
    parser.add_argument("--serve", action="store_true", help="Start a local web server to preview the file")
    parser.add_argument("--zip", action="store_true", help="Create a ZIP of the Swagger file for download")
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument("--json-only", action="store_true", help="Write only JSON output")
    fmt.add_argument("--yaml-only", action="store_true", help="Write only YAML output")
    parser.add_argument("--env", help="Optional Postman environment JSON file to load variables from")
    args = parser.parse_args()

    try:
        styled_print(f"Loading Postman collection: {args.postman}", "run")
        builder = EnhancedSwaggerBuilder(postman_path=args.postman)

        if args.env:
            builder.load_environment_json(args.env)
        # NEW: actually load the Postman environment (if provided)
        if args.env:
            builder.load_environment_json(args.env)

        swagger_data = builder.convert_to_swagger()
        swagger_data = enhance_swagger(swagger_data)

        # NEW: final pass to dedupe params at path/operation level
        swagger_data = process_openapi(swagger_data)

        base_output = Path(args.output).resolve()
        wrote_json = wrote_yaml = False

        if not args.yaml_only:
            json_path = base_output.with_suffix(".json")
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(swagger_data, f, indent=2, ensure_ascii=False)
            styled_print(f"Swagger JSON saved to: {json_path}", "ok")
            wrote_json = True

        if not args.json_only:
            try:
                import yaml
            except Exception:
                styled_print("PyYAML not installed. Skipping YAML export.", "warn")
            else:
                yaml_path = base_output.with_suffix(".yaml")
                with open(yaml_path, "w", encoding="utf-8") as yf:
                    yaml.safe_dump(swagger_data, yf, sort_keys=False, allow_unicode=True)
                styled_print(f"Swagger YAML saved to: {yaml_path}", "ok")
                wrote_yaml = True

        if args.zip:
            if wrote_json:
                zip_path = zip_output(base_output.with_suffix(".json"))
            elif wrote_yaml:
                zip_path = zip_output(base_output.with_suffix(".yaml"))
            else:
                zip_path = None
            if zip_path:
                styled_print(f"ZIP file created: {zip_path}", "ok")

        if args.open_ui and wrote_json:
            webbrowser.open(f"file://{base_output.with_suffix('.json')}")
            styled_print("Swagger file opened in browser.", "info")

        if args.serve and (wrote_json or wrote_yaml):
            serve_file(base_output.with_suffix(".json" if wrote_json else ".yaml"))
            styled_print("Press Ctrl+C to stop the server.", "warn")
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        styled_print("Interrupted by user.", "warn")
        sys.exit(130)
    except Exception as e:
        styled_print(f"Conversion error: {e}", "fail")
        sys.exit(1)


if __name__ == "__main__":
    main()
