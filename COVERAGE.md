# Corpus Coverage

This document describes the completeness and scope of data ingested into the Estonian Cybersecurity MCP server.

## Data Sources

| Source | Authority | URL |
|--------|-----------|-----|
| RIA — Riigi Infosüsteemi Amet | Information System Authority of Estonia | https://www.ria.ee/ |
| CERT-EE | Estonian Computer Emergency Response Team | https://www.ria.ee/en/cyber-security/cert-ee.html |

## Guidance Documents

| Series | Description | Status |
|--------|-------------|--------|
| ISKE | Estonian Information Security Standard — security class requirements for public sector IT systems | Current |
| RIA-juhend | RIA cybersecurity guidance documents and best-practice recommendations | Current |
| NIS2 | NIS2 Directive implementation guidance for Estonian operators | Current |

**Document types covered:** directive, guideline, standard, recommendation

**Document statuses:** current, superseded, draft

## Security Advisories

Source: CERT-EE security advisories published at ria.ee.

**Severity levels:** critical, high, medium, low

**Fields per advisory:** reference, title, date, severity, affected_products, summary, full_text, cve_references

## Frameworks

| ID | Name | Description |
|----|------|-------------|
| ISKE | Infosüsteemide turvameetmete süsteem | Estonian Information Security Standard for public sector |
| RIA-juhend | RIA guidance series | RIA cybersecurity guidance and recommendations |
| NIS2 | NIS2 framework | National NIS2 Directive implementation framework |

## Date Ranges

Date ranges depend on the most recent ingestion run. Use the `ee_cyber_check_data_freshness` tool to retrieve the latest ingestion timestamps programmatically.

## Machine-Readable Coverage

See [data/coverage.json](data/coverage.json) for machine-readable coverage metadata.
