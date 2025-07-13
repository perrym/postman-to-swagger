# APISCAN
# 
# Licensed under the MIT License. 
# Copyright (c) 2025 Perry Mertens
#
# See the LICENSE file for full license text.
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
from version import __version__
import yaml

class EnhancedSwaggerBuilder:
    def __init__(self, postman_path: str):
        self.postman_path = Path(postman_path)
        self.postman_data = self._load_postman()
        self.operation_ids = set()
        self.path_counter = {}
        self.parameter_tracker = {}
        self.server_variables = {}  

    def _generate_unique_operation_id(self, name: str) -> str:
        # Generate a unique operationId
        base_id = re.sub(r'[^a-zA-Z0-9_]', '_', name.lower())
        if base_id not in self.operation_ids:
            self.operation_ids.add(base_id)
            return base_id
        
        # Append suffix if needed
        counter = 1
        while f"{base_id}_{counter}" in self.operation_ids:
            counter += 1
        unique_id = f"{base_id}_{counter}"
        self.operation_ids.add(unique_id)
        return unique_id

    def _load_postman(self) -> dict:
        if not self.postman_path.exists():
            raise FileNotFoundError(f"File not found: {self.postman_path}")
        with open(self.postman_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        if 'info' not in data or 'item' not in data:
            raise ValueError("Invalid Postman structure")
        return data

    def _get_base_url(self) -> str:
        # Retrieve base URL from Postman variables or first request
        variables = self.postman_data.get('variable', [])
        base_url = next((v['value'] for v in variables if v.get('key') == 'baseUrl'), '')

        if not base_url:
            first_request = self._find_first_request(self.postman_data.get('item', []))
            if first_request:
                url = first_request.get('request', {}).get('url')
                if isinstance(url, dict):
                    base_url = f"{url.get('protocol', 'https')}://{'.'.join(url.get('host', []))}"
                elif isinstance(url, str):
                    base_url = urlparse(url).netloc

        # Remove trailing slash
        base_url = base_url.rstrip('/')

        # Process URL variables (e.g., {{env}})
        if base_url:
            placeholders = re.findall(r"{{(.*?)}}", base_url)
            if placeholders:
                self.server_variables = {
                    name: {
                        "default": f"example.{name}.com",
                        "description": f"Variable '{name}' automatically generated"
                    } for name in placeholders
                }
                base_url = re.sub(r"{{(.*?)}}", r"{\1}", base_url)
            else:
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

        # Safety fallback if not defined elsewhere
        if not hasattr(self, 'server_variables'):
            self.server_variables = {
                "baseUrl": {
                    "default": base_url,
                    "description": "Default URL"
                }
            }

        return base_url


    
    def convert_to_swagger(self) -> dict:
        base_url = self._get_base_url()
        swagger = {
            "openapi": "3.0.0",
            "info": {
                "title": self.postman_data.get('info', {}).get('name', 'Converted from Postman'),
                "version": self.postman_data.get('info', {}).get('schema', '1.0.0').split('/')[-1],
                "description": self.postman_data.get('info', {}).get('description', ''),
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
                {
                    "name": "default",
                    "description": "General API endpoints"
                }
            ],
            "servers": [{
                "url": base_url,
                "variables": self.server_variables
            }],
            "paths": {},
            "components": {
                "securitySchemes": self._extract_auth_schemes()
            },
            "security": self._build_security_blocks()
        }

        self._process_items(self.postman_data.get('item', []), swagger['paths'])
        return swagger

    def normalize_path(path: str) -> str:
        #Converteer Postman-achtige path notatie zoals :id en {{var}} naar OpenAPI {id} notatie.
        # :id → {id}
        path = re.sub(r":(\w+)", r"{\1}", path)
        # {{var}} → {var}
        path = re.sub(r"{{(.*?)}}", r"{\1}", path)
        return path

    
    def _parse_url(self, url: Dict|str) -> Tuple[str, List]:
        """Parse Postman URL naar OpenAPI path en unieke parameters"""
        if isinstance(url, str):
            parsed = urlparse(url)
            path = parsed.path or '/unnamed_path'
            query_params = self._parse_query_string(parsed.query)
            path_params = self._extract_path_parameters(path)
            return path, path_params + query_params

        raw_path = '/' + '/'.join(url.get('path', ['unnamed_path']))
        path = re.sub(r"{{(.*?)}}", r"{\1}", raw_path)

        query_params = []
        for param in url.get('query', []):
            if not param.get('key') or not isinstance(param['key'], str):
                continue
            query_params.append({
                "name": str(param['key']),
                "in": "query",
                "description": param.get('description', '') or 'No description',
                "required": not param.get('disabled', False),
                "schema": {"type": "string"}
            })

        path_params = self._extract_path_parameters(path)
        return path, path_params + query_params

    def _extract_path_parameters(self, path: str) -> List[Dict]:
        # Identify parameters in URL template
        return [
            {
                "name": param_name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": f"URL path parameter {param_name}"
            }
            for param_name in set(re.findall(r'{(.*?)}', path))  # Gebruik set() voor unieke waarden
        ]



    def _find_first_request(self, items):
        for item in items:
            if 'item' in item:
                found = self._find_first_request(item['item'])
                if found:
                    return found
            elif 'request' in item:
                return item
        return None

    def _extract_auth_schemes(self) -> Dict:
        return {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT"
            },
            "basicAuth": {
                "type": "http",
                "scheme": "basic"
            },
            "apiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key"
            },
            "clientCredentials": {
                "type": "oauth2",
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "https://example.com/oauth/token",
                        "scopes": {
                            "read": "Read access",
                            "write": "Write access"
                        }
                    }
                }
            }
        }

    def _build_security_blocks(self) -> List[Dict]:
        return [
            {"bearerAuth": []},
            {"basicAuth": []},
            {"apiKeyAuth": []},
            {"clientCredentials": ["read", "write"]}
        ]

    def _process_items(self, items: List, paths: Dict, current_folder: str = '') -> None:
        for item in items:
            if 'item' in item:
                self._process_items(item['item'], paths)
            else:
                self._add_request_to_paths(item, paths)

    def _add_request_to_paths(self, item: Dict, paths: Dict) -> None:
        request = item.get('request', {})
        if not request:
            return

        method = request.get('method', 'GET').lower()
        url = request.get('url')
        if not url:
            return

        path, parameters = self._parse_url(url)
        
        # Validate and correct path
        if not path or path == '/':
            path = '/unnamed_path'
            styled_print(f"Empty path found, replaced with {path}", "warn")

        # Track path usage
        self.path_counter[path] = self.path_counter.get(path, 0) + 1

        if path not in paths:
            paths[path] = {}

        # Validate and correct parameters
        parameters = self._validate_and_deduplicate_parameters(path, method, parameters)

        operation = {
            "summary": item.get('name', 'Unnamed endpoint') or 'Unnamed endpoint',
            "description": request.get('description', '') or 'No description available',
            "parameters": parameters,
            "tags": [item.get('name', 'default').replace(' ', '_')[:20]],
            "operationId": self._generate_unique_operation_id(item.get('name', f"{method}_{path}")),
            "responses": self._parse_responses(request)
        }

        if method != "get":
            body = self._parse_request_body(request)
            if body:
                operation["requestBody"] = body

        paths[path][method] = operation

       
    
    def _parse_query_string(self, query: str) -> List:
        if not query:
            return []

        params = []
        for pair in query.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                params.append({
                    "name": key,
                    "in": "query",
                    "schema": {"type": "string"},
                    "example": value
                })
        return params

    def _parse_request_body(self, request: Dict) -> Optional[Dict]:
        body = request.get('body')
        if not body:
            return None

        content_type = next(
            (header['value'] for header in request.get('header', [])
             if header.get('key', '').lower() == 'content-type'),
            'application/json')

        if body.get('mode') == 'raw':
            try:
                json_body = json.loads(body.get('raw', '{}'))
                return {
                    "content": {
                        content_type: {
                            "schema": self._json_to_schema(json_body)
                        }
                    }
                }
            except json.JSONDecodeError:
                return {
                    "content": {
                        content_type: {
                            "schema": {"type": "string"},
                            "example": body.get('raw')
                        }
                    }
                }
        return None

    def _json_to_schema(self, data: Any) -> Dict:
        """Zorg altijd voor geldige array schema's"""
        if isinstance(data, dict):
            properties = {}
            required = []
            for k, v in data.items():
                properties[k] = self._json_to_schema(v)
                if v is not None:
                    required.append(k)
            schema = {
                "type": "object",
                "properties": properties
            }
            if required:
                schema["required"] = required
            return schema
        elif isinstance(data, list):
            if data:
                return {
                    "type": "array",
                    "items": self._json_to_schema(data[0])
                }
            else:
                # Ensure 'items' is always present, even in empty arrays
                return {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "description": "Example: empty list"
                    }
                }
        else:
            py_type = type(data).__name__
            type_map = {
                "str": "string", "int": "integer", 
                "float": "number", "bool": "boolean",
                "NoneType": "string"
            }
            return {"type": type_map.get(py_type, "string")}

        
    def _parse_responses(self, request: Dict) -> Dict:
        responses = {
            "200": {
                "description": "Successful operation",
                "content": {
                    "application/json": {
                        "example": {"status": "success"}
                    }
                }
            },
            "400": {
                "description": "Invalid input",
                "content": {
                    "application/json": {
                        "example": {"error": "Invalid input"}
                    }
                }
            },
            "500": {
                "description": "Server error",
                "content": {
                    "application/json": {
                        "example": {"error": "Internal server error"}
                    }
                }
            }
        }

        examples = request.get('response', [])
        for example in examples:
            code = str(example.get('code', '200'))
            if code not in responses:
                responses[code] = {
                    "description": example.get('name', 'Example response') or 'No description',
                    "content": {
                        example.get('header', {}).get('content-type', 'application/json'): {
                            "example": example.get('body') or {}
                        }
                    }
                }

        return responses


    def _validate_and_deduplicate_parameters(self, path: str, method: str, parameters: List[Dict]) -> List[Dict]:
        """Valideer en verwijder dubbele parameters met geavanceerde logging"""
        unique_params = []
        seen_params = set()
        duplicates = []

        for param in parameters:
            param_key = (param['name'].lower(), param['in'])  # Case-insensitive matching
            
            if param_key in seen_params:
                duplicates.append(param['name'])
                continue
                
            seen_params.add(param_key)
            unique_params.append(param)

        if duplicates:
            styled_print(
                f"Warning: Duplicate parameters {duplicates} verwijderd uit {method.upper()} {path}",
                "warn"
            )
            
        # Add missing path parameters
        path_params_in_url = set(re.findall(r'{(.*?)}', path))
        defined_path_params = set(
            p['name'] for p in unique_params 
            if p.get('in') == 'path'
        )
        
        missing_path_params = path_params_in_url - defined_path_params
        for param_name in missing_path_params:
            unique_params.append({
                "name": param_name,
                "in": "path",
                "required": True,
                "schema": {"type": "string"},
                "description": f"Auto-generated path parameter {param_name}"
            })
            styled_print(
                f"Warning: Missing path parameter '{param_name}' added to {method.upper()} {path}",
                "warn"
            )

        return unique_params
    
    def _deduplicate_parameters(self, params: List[Dict]) -> List[Dict]:
        """Verwijder dubbele parameters en behoud de laatste instantie"""
        seen = set()
        unique_params = []
        
        for param in reversed(params):
            param_id = (param['name'], param['in'])
            if param_id not in seen:
                seen.add(param_id)
                unique_params.append(param)
        
        return list(reversed(unique_params))

    def enrich_description(summary: str, existing: str = "") -> str:
        if existing and existing.strip().lower() != "no description available":
            return existing
        return f"This endpoint handles the action: '{summary}'. More details to be documented."

        def apply_descriptions_to_operations(paths: dict) -> None:
            for path, methods in paths.items():
                for method, op in methods.items():
                    summary = op.get("summary", "No summary")
                    op["description"] = enrich_description(summary, op.get("description", ""))

        def extract_inline_schemas(paths: dict, components: dict) -> None:
            for path_item in paths.values():
                for method in path_item.values():
                    if not isinstance(method, dict):
                        continue
                    if 'requestBody' in method:
                        content = method['requestBody'].get('content', {})
                        for media_type, media_def in content.items():
                            schema = media_def.get('schema')
                            if schema:
                                ref_name = _store_schema(schema, components)
                                media_def['schema'] = {"$ref": f"#/components/schemas/{ref_name}"}
                    for resp in method.get('responses', {}).values():
                        content = resp.get('content', {})
                        for media_type, media_def in content.items():
                            schema = media_def.get('schema')
                            if schema:
                                ref_name = _store_schema(schema, components)
                                media_def['schema'] = {"$ref": f"#/components/schemas/{ref_name}"}

        def _store_schema(schema: dict, components: dict) -> str:
            schema_str = str(schema).encode('utf-8')
            ref_name = 'Schema_' + hashlib.sha1(schema_str).hexdigest()[:8]
            if 'schemas' not in components:
                components['schemas'] = {}
            if ref_name not in components['schemas']:
                components['schemas'][ref_name] = schema
            return ref_name

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
        
    

def enrich_description(summary: str, existing: str = "") -> str:
    if existing and existing.strip().lower() != "no description available":
        return existing
    return f"This endpoint handles the action: '{summary}'. More details to be documented."

def apply_descriptions_to_operations(paths: dict) -> None:
    for path, methods in paths.items():
        for method, op in methods.items():
            summary = op.get("summary", "No summary")
            op["description"] = enrich_description(summary, op.get("description", ""))

def extract_inline_schemas(paths: dict, components: dict) -> None:
    for path_item in paths.values():
        for method in path_item.values():
            if not isinstance(method, dict):
                continue
            if 'requestBody' in method:
                content = method['requestBody'].get('content', {})
                for media_type, media_def in content.items():
                    schema = media_def.get('schema')
                    if schema:
                        ref_name = _store_schema(schema, components)
                        media_def['schema'] = {"$ref": f"#/components/schemas/{ref_name}"}
            for resp in method.get('responses', {}).values():
                content = resp.get('content', {})
                for media_type, media_def in content.items():
                    schema = media_def.get('schema')
                    if schema:
                        ref_name = _store_schema(schema, components)
                        media_def['schema'] = {"$ref": f"#/components/schemas/{ref_name}"}

def _store_schema(schema: dict, components: dict) -> str:
    import hashlib
    schema_str = str(schema).encode('utf-8')
    ref_name = 'Schema_' + hashlib.sha1(schema_str).hexdigest()[:8]
    if 'schemas' not in components:
        components['schemas'] = {}
    if ref_name not in components['schemas']:
        components['schemas'][ref_name] = schema
    return ref_name

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


def styled_print(message: str, status: str = "info"):
    symbols = {
        "info": "[i]",
        "ok": "[✓]",
        "warn": "[!]",
        "fail": "[✗]",
        "run": "[→]",
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


def serve_file(path: Path, port: int = 8000):
    class CustomHandler(SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

    def start_server():
        httpd = HTTPServer(('localhost', port), CustomHandler)
        styled_print(f"Start tijdelijke webserver op http://localhost:{port}/", "info")
        webbrowser.open(f"http://localhost:{port}/{path.name}")
        httpd.serve_forever()

    threading.Thread(target=start_server, daemon=True).start()
    time.sleep(2)


def zip_output(swagger_path: Path) -> Path:
    zip_path = swagger_path.with_suffix(".zip")
    with zipfile.ZipFile(zip_path, 'w') as zipf:
        zipf.write(swagger_path, arcname=swagger_path.name)
    return zip_path


def main():
    parser = argparse.ArgumentParser(description="Convert a Postman v2.1 collection to OpenAPI 3.0 Swagger (c) Perry Mertens 2025.")
    parser.add_argument("--postman", required=True, help="Path to Postman .json file")
    parser.add_argument("--output", default="openapi_output.json", help="Name of the output Swagger file")
    parser.add_argument("--open-ui", action="store_true", help="Open Swagger JSON in default browser")
    parser.add_argument("--serve", action="store_true", help="Start a local web server to preview the file")
    parser.add_argument("--zip", action="store_true", help="Create a ZIP of the Swagger file for download")

    args = parser.parse_args()

    try:
        styled_print(f"Loading Postman collection: {args.postman}", "run")
        builder = EnhancedSwaggerBuilder(postman_path=args.postman)
        swagger_data = builder.convert_to_swagger()

        # ✅ CORRECT INGEDRAGEN
        swagger_data = enhance_swagger(swagger_data)

        output_path = Path(args.output).resolve()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(swagger_data, f, indent=2)
        # YAML export
        try:
            import yaml
            yaml_output = output_path.with_suffix(".yaml")
            with open(yaml_output, "w", encoding="utf-8") as yf:
                yaml.dump(swagger_data, yf, sort_keys=False)
            styled_print(f"YAML file successfully saved to: {yaml_output}", "ok")
        except ImportError:
            styled_print("PyYAML not installed. Skipping YAML export.", "warn")


        styled_print(f"Swagger file successfully saved to: {output_path}", "ok")

        if args.zip:
            zip_path = zip_output(output_path)
            styled_print(f"ZIP file created: {zip_path}", "ok")

        if args.open_ui:
            webbrowser.open(f"file://{output_path}")
            styled_print("Swagger file opened in browser.", "info")

        if args.serve:
            serve_file(output_path)
            styled_print("Press Ctrl+C to stop the server.", "warn")
            while True:
                time.sleep(1)

    except Exception as e:
        styled_print(f"Conversion error: {e}", "fail")


if __name__ == "__main__":
    main()
