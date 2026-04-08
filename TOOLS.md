# Tool Reference

All tools are prefixed with `ee_cyber_` and available via both stdio (`src/index.ts`) and HTTP (`src/http-server.ts`) transports.

---

## ee_cyber_search_guidance

Full-text search across RIA cybersecurity guidelines, directives, and technical standards.

**Parameters**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | yes | Search terms (e.g., `'ISKE turvaklass'`, `'intsidentide käsitlemine'`) |
| `type` | string | no | Filter by document type: `directive`, `guideline`, `standard`, `recommendation` |
| `series` | string | no | Filter by RIA series: `ISKE`, `RIA-juhend`, `NIS2` |
| `status` | string | no | Filter by status: `current`, `superseded`, `draft` |
| `limit` | number | no | Max results to return (default: 20, max: 100) |

**Example**
```json
{ "query": "ISKE turvaklass", "series": "ISKE", "status": "current", "limit": 10 }
```

---

## ee_cyber_get_guidance

Retrieve a specific RIA guidance document by its reference identifier.

**Parameters**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `reference` | string | yes | Document reference (e.g., `'RIA-ISKE-2023'`, `'RIA-juhend-001'`) |

**Example**
```json
{ "reference": "RIA-ISKE-2023" }
```

**Response extras:** includes `_citation` metadata for deterministic citation verification.

---

## ee_cyber_search_advisories

Search CERT-EE security advisories and incident alerts.

**Parameters**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `query` | string | yes | Search terms (e.g., `'kriitiline haavatavus'`, `'lunavara'`) |
| `severity` | string | no | Filter by severity: `critical`, `high`, `medium`, `low` |
| `limit` | number | no | Max results to return (default: 20, max: 100) |

**Example**
```json
{ "query": "lunavara", "severity": "critical", "limit": 5 }
```

---

## ee_cyber_get_advisory

Retrieve a specific CERT-EE security advisory by its reference identifier.

**Parameters**

| Name | Type | Required | Description |
|------|------|----------|-------------|
| `reference` | string | yes | Advisory reference (e.g., `'CERT-EE-2024-001'`) |

**Example**
```json
{ "reference": "CERT-EE-2024-001" }
```

**Response extras:** includes `_citation` metadata for deterministic citation verification.

---

## ee_cyber_list_frameworks

List all RIA/CERT-EE cybersecurity frameworks covered in this MCP.

**Parameters:** none

**Example**
```json
{}
```

---

## ee_cyber_about

Return metadata about this MCP server: version, data source, coverage summary, and tool list.

**Parameters:** none

**Example**
```json
{}
```

---

## ee_cyber_list_sources

Return data source URLs and descriptions for all content in this MCP.

**Parameters:** none

**Example**
```json
{}
```

**Response**
```json
{
  "sources": [
    {
      "name": "RIA — Riigi Infosüsteemi Amet",
      "url": "https://www.ria.ee/",
      "description": "Primary source for Estonian cybersecurity guidelines..."
    },
    {
      "name": "CERT-EE",
      "url": "https://www.ria.ee/en/cyber-security/cert-ee.html",
      "description": "Estonian CERT — source for security advisories..."
    }
  ]
}
```

---

## ee_cyber_check_data_freshness

Return the latest ingestion dates for guidance and advisory data in this MCP.

**Parameters:** none

**Example**
```json
{}
```

**Response**
```json
{
  "guidance_latest": "2024-11-15",
  "advisory_latest": "2024-12-01",
  "checked_at": "2026-04-08T12:00:00.000Z"
}
```

---

## Common Response Fields

All tool responses include a `_meta` block:

```json
{
  "_meta": {
    "disclaimer": "For informational purposes only. Verify all information against ria.ee before taking action.",
    "data_age": { "guidance_latest": "...", "advisory_latest": "...", "checked_at": "..." },
    "copyright": "© Riigi Infosüsteemi Amet (RIA)",
    "source_url": "https://www.ria.ee/"
  }
}
```

Point-lookup tools (`ee_cyber_get_guidance`, `ee_cyber_get_advisory`) also include a `_citation` block for deterministic citation verification pipelines.
