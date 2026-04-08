#!/usr/bin/env node

/**
 * HTTP Server Entry Point for Docker Deployment
 *
 * Provides Streamable HTTP transport for remote MCP clients.
 * Use src/index.ts for local stdio-based usage.
 *
 * Endpoints:
 *   GET  /health  — liveness probe
 *   POST /mcp     — MCP Streamable HTTP (session-aware)
 */

import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { randomUUID } from "node:crypto";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import {
  searchGuidance,
  getGuidance,
  searchAdvisories,
  getAdvisory,
  listFrameworks,
  getDataFreshness,
} from "./db.js";
import { buildCitation } from "./citation.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const PORT = parseInt(process.env["PORT"] ?? "3000", 10);
const SERVER_NAME = "estonian-cybersecurity-mcp";

let pkgVersion = "0.1.0";
try {
  const pkg = JSON.parse(
    readFileSync(join(__dirname, "..", "package.json"), "utf8"),
  ) as { version: string };
  pkgVersion = pkg.version;
} catch {
  // fallback
}

// --- Tool definitions (shared with index.ts) ---------------------------------

const TOOLS = [
  {
    name: "ee_cyber_search_guidance",
    description:
      "Full-text search across RIA cybersecurity guidelines, directives, and technical standards. Covers ISKE security framework requirements, RIA guidance documents, NIS2 implementation guidance, and national cybersecurity strategy documents. Returns matching documents with reference, title, series, and summary.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'ISKE turvaklass, intsidentide käsitlemine')" },
        type: {
          type: "string",
          enum: ["directive", "guideline", "standard", "recommendation"],
          description: "Filter by document type. Optional.",
        },
        series: {
          type: "string",
          enum: ["ISKE", "RIA-juhend", "NIS2"],
          description: "Filter by RIA series. Optional.",
        },
        status: {
          type: "string",
          enum: ["current", "superseded", "draft"],
          description: "Filter by document status. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "ee_cyber_get_guidance",
    description:
      "Get a specific RIA guidance document by reference (e.g., 'RIA-ISKE-2023', 'RIA-juhend-001', 'CERT-EE-TG-2024-01').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "RIA document reference (e.g., 'RIA-ISKE-2023', 'RIA-juhend-001')" },
      },
      required: ["reference"],
    },
  },
  {
    name: "ee_cyber_search_advisories",
    description:
      "Search CERT-EE security advisories and incident alerts. Returns advisories with severity, affected products, and CVE references where available.",
    inputSchema: {
      type: "object" as const,
      properties: {
        query: { type: "string", description: "Search query (e.g., 'kriitiline haavatavus, lunavara')" },
        severity: {
          type: "string",
          enum: ["critical", "high", "medium", "low"],
          description: "Filter by severity level. Optional.",
        },
        limit: { type: "number", description: "Max results (default 20)." },
      },
      required: ["query"],
    },
  },
  {
    name: "ee_cyber_get_advisory",
    description: "Get a specific CERT-EE security advisory by reference (e.g., 'CERT-EE-2024-001').",
    inputSchema: {
      type: "object" as const,
      properties: {
        reference: { type: "string", description: "CERT-EE advisory reference (e.g., 'CERT-EE-2024-001')" },
      },
      required: ["reference"],
    },
  },
  {
    name: "ee_cyber_list_frameworks",
    description:
      "List all RIA/CERT-EE cybersecurity frameworks covered in this MCP, including ISKE, national cybersecurity strategy, and NIS2 implementation framework.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "ee_cyber_about",
    description: "Return metadata about this MCP server: version, data source, coverage, and tool list.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "ee_cyber_list_sources",
    description: "Return data source URLs and descriptions for all content in this MCP.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
  {
    name: "ee_cyber_check_data_freshness",
    description: "Return the latest ingestion dates for guidance and advisory data in this MCP.",
    inputSchema: { type: "object" as const, properties: {}, required: [] },
  },
];

// --- Zod schemas -------------------------------------------------------------

const SearchGuidanceArgs = z.object({
  query: z.string().min(1),
  type: z.enum(["directive", "guideline", "standard", "recommendation"]).optional(),
  series: z.enum(["ISKE", "RIA-juhend", "NIS2"]).optional(),
  status: z.enum(["current", "superseded", "draft"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetGuidanceArgs = z.object({
  reference: z.string().min(1),
});

const SearchAdvisoriesArgs = z.object({
  query: z.string().min(1),
  severity: z.enum(["critical", "high", "medium", "low"]).optional(),
  limit: z.number().int().positive().max(100).optional(),
});

const GetAdvisoryArgs = z.object({
  reference: z.string().min(1),
});

// --- Meta helper -------------------------------------------------------------

function buildMeta(): Record<string, unknown> {
  let data_age: unknown = null;
  try {
    data_age = getDataFreshness();
  } catch {
    // DB not yet initialised
  }
  return {
    disclaimer:
      "For informational purposes only. Verify all information against ria.ee before taking action.",
    data_age,
    copyright: "© Riigi Infosüsteemi Amet (RIA)",
    source_url: "https://www.ria.ee/",
  };
}

// --- MCP server factory ------------------------------------------------------

function createMcpServer(): Server {
  const server = new Server(
    { name: SERVER_NAME, version: pkgVersion },
    { capabilities: { tools: {} } },
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: TOOLS,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;

    function textContent(data: unknown) {
      return {
        content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
      };
    }

    function errorContent(message: string) {
      return {
        content: [{ type: "text" as const, text: message }],
        isError: true as const,
      };
    }

    try {
      switch (name) {
        case "ee_cyber_search_guidance": {
          const parsed = SearchGuidanceArgs.parse(args);
          const results = searchGuidance({
            query: parsed.query,
            type: parsed.type,
            series: parsed.series,
            status: parsed.status,
            limit: parsed.limit,
          });
          return textContent({ results, count: results.length, _meta: buildMeta() });
        }

        case "ee_cyber_get_guidance": {
          const parsed = GetGuidanceArgs.parse(args);
          const doc = getGuidance(parsed.reference);
          if (!doc) {
            return errorContent(`Guidance document not found: ${parsed.reference}`);
          }
          const guidanceRecord = doc as unknown as Record<string, unknown>;
          return textContent({
            ...guidanceRecord,
            _citation: buildCitation(
              String(guidanceRecord["reference"] ?? parsed.reference),
              String(guidanceRecord["title"] ?? guidanceRecord["reference"] ?? parsed.reference),
              "ee_cyber_get_guidance",
              { reference: parsed.reference },
              guidanceRecord["url"] as string | undefined,
            ),
            _meta: buildMeta(),
          });
        }

        case "ee_cyber_search_advisories": {
          const parsed = SearchAdvisoriesArgs.parse(args);
          const results = searchAdvisories({
            query: parsed.query,
            severity: parsed.severity,
            limit: parsed.limit,
          });
          return textContent({ results, count: results.length, _meta: buildMeta() });
        }

        case "ee_cyber_get_advisory": {
          const parsed = GetAdvisoryArgs.parse(args);
          const advisory = getAdvisory(parsed.reference);
          if (!advisory) {
            return errorContent(`Advisory not found: ${parsed.reference}`);
          }
          const advisoryRecord = advisory as unknown as Record<string, unknown>;
          return textContent({
            ...advisoryRecord,
            _citation: buildCitation(
              String(advisoryRecord["reference"] ?? parsed.reference),
              String(advisoryRecord["title"] ?? advisoryRecord["reference"] ?? parsed.reference),
              "ee_cyber_get_advisory",
              { reference: parsed.reference },
              advisoryRecord["url"] as string | undefined,
            ),
            _meta: buildMeta(),
          });
        }

        case "ee_cyber_list_frameworks": {
          const frameworks = listFrameworks();
          return textContent({ frameworks, count: frameworks.length, _meta: buildMeta() });
        }

        case "ee_cyber_about": {
          return textContent({
            name: SERVER_NAME,
            version: pkgVersion,
            description:
              "RIA (Riigi Infosüsteemi Amet — Information System Authority of Estonia) and CERT-EE MCP server. Provides access to Estonian national cybersecurity guidelines, ISKE security framework requirements, NIS2 implementation directives, and CERT-EE security advisories.",
            data_source: "RIA / CERT-EE (https://www.ria.ee/)",
            coverage: {
              guidance: "ISKE security framework, RIA cybersecurity guidelines, NIS2 implementation directives",
              advisories: "CERT-EE security advisories and incident alerts",
              frameworks: "ISKE, national cybersecurity strategy, NIS2 framework",
            },
            tools: TOOLS.map((t) => ({ name: t.name, description: t.description })),
            _meta: buildMeta(),
          });
        }

        case "ee_cyber_list_sources": {
          return textContent({
            sources: [
              {
                name: "RIA — Riigi Infosüsteemi Amet (Information System Authority of Estonia)",
                url: "https://www.ria.ee/",
                description:
                  "Primary source for Estonian cybersecurity guidelines, ISKE framework, and national cybersecurity strategy documents.",
              },
              {
                name: "CERT-EE",
                url: "https://www.ria.ee/en/cyber-security/cert-ee.html",
                description:
                  "Estonian Computer Emergency Response Team — source for security advisories and incident alerts.",
              },
            ],
            _meta: buildMeta(),
          });
        }

        case "ee_cyber_check_data_freshness": {
          const freshness = getDataFreshness();
          return textContent({ ...freshness, _meta: buildMeta() });
        }

        default:
          return errorContent(`Unknown tool: ${name}`);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      return errorContent(`Error executing ${name}: ${message}`);
    }
  });

  return server;
}

// --- HTTP server -------------------------------------------------------------

async function main(): Promise<void> {
  const sessions = new Map<
    string,
    { transport: StreamableHTTPServerTransport; server: Server }
  >();

  const httpServer = createServer((req, res) => {
    handleRequest(req, res, sessions).catch((err) => {
      console.error(`[${SERVER_NAME}] Unhandled error:`, err);
      if (!res.headersSent) {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: "Internal server error" }));
      }
    });
  });

  async function handleRequest(
    req: import("node:http").IncomingMessage,
    res: import("node:http").ServerResponse,
    activeSessions: Map<
      string,
      { transport: StreamableHTTPServerTransport; server: Server }
    >,
  ): Promise<void> {
    const url = new URL(req.url ?? "/", `http://localhost:${PORT}`);

    if (url.pathname === "/health") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: SERVER_NAME, version: pkgVersion }));
      return;
    }

    if (url.pathname === "/mcp") {
      const sessionId = req.headers["mcp-session-id"] as string | undefined;

      if (sessionId && activeSessions.has(sessionId)) {
        const session = activeSessions.get(sessionId)!;
        await session.transport.handleRequest(req, res);
        return;
      }

      const mcpServer = createMcpServer();
      const transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      // eslint-disable-next-line @typescript-eslint/no-explicit-any -- SDK type mismatch with exactOptionalPropertyTypes
      await mcpServer.connect(transport as any);

      transport.onclose = () => {
        if (transport.sessionId) {
          activeSessions.delete(transport.sessionId);
        }
        mcpServer.close().catch(() => {});
      };

      await transport.handleRequest(req, res);

      if (transport.sessionId) {
        activeSessions.set(transport.sessionId, { transport, server: mcpServer });
      }
      return;
    }

    res.writeHead(404, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ error: "Not found" }));
  }

  httpServer.listen(PORT, () => {
    console.error(`${SERVER_NAME} v${pkgVersion} (HTTP) listening on port ${PORT}`);
    console.error(`MCP endpoint:  http://localhost:${PORT}/mcp`);
    console.error(`Health check:  http://localhost:${PORT}/health`);
  });

  process.on("SIGTERM", () => {
    console.error("Received SIGTERM, shutting down...");
    httpServer.close(() => process.exit(0));
  });
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
