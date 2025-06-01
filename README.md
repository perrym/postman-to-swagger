APISCAN – Postman v2.1 ➜ OpenAPI 3.0 Converter




APISCAN is a command‑line tool that transforms a Postman v2.1 collection into a fully‑linted OpenAPI 3.0 (Swagger) specification—JSON and YAML—ready for publishing or further automation. It enriches the generated spec with smart defaults, unique operationIds, deduplicated parameters, and robust security schemes so you can focus on building great APIs instead of hand‑crafting docs.

Key Features

Feature

Why it matters

Enhanced Swagger Builder

Generates unique operation IDs, fixes malformed paths, and fills in missing path/query parameters.

Automatic server detection

Deduces a base URL from collection variables or the first request; graceful fallbacks included.

Rich security definitions

Adds bearer, basic, apiKey, and OAuth 2.0 client‑credentials blocks out of the box.

Inline‑schema extraction

Promotes inline request/response schemas into components/schemas for reuse and clarity.

Multi‑format output

Saves both openapi_output.json and openapi_output.yaml; can optionally ZIP them for sharing.

One‑liner web preview

--serve spins up a tiny HTTP server and opens your default browser to inspect the spec instantly.

🚀 Quick Start

1. Install

python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install -r requirements.txt  # Only PyYAML is required

Prerequisite: Python 3.8 or newer.

2. Convert your collection

python postman-to-swagger.py \
  --postman MyCollection.postman_collection.json \
  --output openapi_output.json \
  --open-ui \
  --serve

Flag

Purpose

--postman (required)

Path to your Postman v2.1 collection file

--output

Base filename for the JSON spec (YAML is auto‑generated too)

--open-ui

Opens the generated JSON in your default browser

--serve

Starts a local preview server at http://localhost:8000

--zip

Creates a ZIP archive containing the spec files

🖥️ Example Output

{
  "openapi": "3.0.0",
  "info": {
    "title": "Sample API",
    "version": "1.0.0",
    "description": "Converted from Postman"
  },
  "servers": [
    {
      "url": "https://api.example.com",
      "variables": {
        "baseUrl": {
          "default": "https://api.example.com",
          "description": "Base server URL"
        }
      }
    }
  ],
  "paths": {
    "/users/{id}": {
      "get": {
        "summary": "Get user by ID",
        "operationId": "get_user_by_id",
        "responses": { "200": { "description": "Successful operation" } }
      }
    }
  }
}

🛠️ Contributing

Fork the repository and create your branch (git checkout -b feature/awesome).

Ensure code is formatted with Black and passes flake8.

Write or update tests where appropriate.

Open a pull request—templates and GitHub Actions will guide you through linting & CI.

We love new features and bug‑fixes! Please open an issue first if you plan a large change so we can discuss design & scope.

📝 License

This project is licensed under the MIT License—see the LICENSE file for details. © 2025 Perry Mertens.

Need Help?

Bug reports / questions: Open an issue.

Security concerns: Please email security@your‑domain.com instead of filing a public ticket.

General chat: Join the GitHub Discussions board.

Happy converting! 
