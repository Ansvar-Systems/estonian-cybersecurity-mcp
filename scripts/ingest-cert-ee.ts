/**
 * Ingestion crawler for CERT-EE / RIA cybersecurity content.
 *
 * Sources:
 *   1. blog.ria.ee (→ redirects to www.ria.ee/blogi) — weekly vulnerability
 *      roundups ("turvanorkused"), international cyber-news, AI security news,
 *      and general cybersecurity guidance articles.
 *   2. www.ria.ee/kuberturvalisus/kuberruumi-analuus-ja-ennetus/olukord-kuberruumis
 *      — monthly "Olukord kuberruumis" situation reports.
 *   3. www.ria.ee/kuberturbe-nouanded — cybersecurity guidance documents and
 *      recommendations for organisations.
 *
 * The crawler writes into the same SQLite schema used by the MCP server
 * (guidance + advisories + frameworks tables, see src/db.ts).
 *
 * Usage:
 *   npx tsx scripts/ingest-cert-ee.ts                  # full crawl
 *   npx tsx scripts/ingest-cert-ee.ts --resume         # skip already-stored references
 *   npx tsx scripts/ingest-cert-ee.ts --dry-run        # fetch & parse, print without writing DB
 *   npx tsx scripts/ingest-cert-ee.ts --force           # drop all rows and re-ingest
 *   npx tsx scripts/ingest-cert-ee.ts --max-pages 5    # limit blog pagination depth
 *
 * Environment:
 *   RIA_DB_PATH  — SQLite database path (default: data/ria.db)
 */

import Database from "better-sqlite3";
import * as cheerio from "cheerio";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

const RATE_LIMIT_MS = 1500;
const MAX_RETRIES = 3;
const RETRY_BACKOFF_MS = 2000;
const REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_PAGES = 50;

const BASE_URL = "https://www.ria.ee";
const BLOG_LISTING = `${BASE_URL}/blogi`;
const SITUATION_REPORTS = `${BASE_URL}/kuberturvalisus/kuberruumi-analuus-ja-ennetus/olukord-kuberruumis`;
const GUIDANCE_ORGS = `${BASE_URL}/kuberturbe-nouanded/nouanded-asutusele-ja-ettevottele`;
const GUIDANCE_USERS = `${BASE_URL}/kuberturbe-nouanded/nouanded-internetikasutajale`;

const USER_AGENT =
  "AnsvarCrawler/1.0 (+https://ansvar.eu; CERT-EE ingestion for cybersecurity MCP)";

// ---------------------------------------------------------------------------
// CLI flags
// ---------------------------------------------------------------------------

const args = process.argv.slice(2);
const FLAG_RESUME = args.includes("--resume");
const FLAG_DRY_RUN = args.includes("--dry-run");
const FLAG_FORCE = args.includes("--force");

function flagValue(name: string, fallback: number): number {
  const idx = args.indexOf(name);
  if (idx === -1 || idx + 1 >= args.length) return fallback;
  const v = parseInt(args[idx + 1], 10);
  return Number.isNaN(v) ? fallback : v;
}
const MAX_PAGES = flagValue("--max-pages", DEFAULT_MAX_PAGES);

// ---------------------------------------------------------------------------
// Database setup
// ---------------------------------------------------------------------------

const DB_PATH = process.env["RIA_DB_PATH"] ?? "data/ria.db";

function openDb(): Database.Database {
  const dir = dirname(DB_PATH);
  if (!existsSync(dir)) mkdirSync(dir, { recursive: true });
  if (FLAG_FORCE && existsSync(DB_PATH)) {
    unlinkSync(DB_PATH);
    console.log(`[db] Deleted existing database: ${DB_PATH}`);
  }
  const db = new Database(DB_PATH);
  db.pragma("journal_mode = WAL");
  db.pragma("foreign_keys = ON");
  db.exec(SCHEMA_SQL);
  return db;
}

// ---------------------------------------------------------------------------
// HTTP helpers with retry + rate-limit
// ---------------------------------------------------------------------------

let lastRequestMs = 0;

async function rateLimitedFetch(url: string): Promise<Response> {
  const now = Date.now();
  const elapsed = now - lastRequestMs;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  lastRequestMs = Date.now();

  let lastError: Error | null = null;
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
      const res = await fetch(url, {
        headers: {
          "User-Agent": USER_AGENT,
          Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
          "Accept-Language": "et,en;q=0.5",
        },
        signal: controller.signal,
        redirect: "follow",
      });
      clearTimeout(timer);

      if (res.ok) return res;

      // Retry on server errors, not on 404/403
      if (res.status >= 500) {
        lastError = new Error(`HTTP ${res.status} for ${url}`);
        console.warn(`[fetch] Attempt ${attempt}/${MAX_RETRIES} — ${lastError.message}`);
        if (attempt < MAX_RETRIES) await sleep(RETRY_BACKOFF_MS * attempt);
        continue;
      }

      throw new Error(`HTTP ${res.status} for ${url}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("abort")) {
        lastError = new Error(`Timeout after ${REQUEST_TIMEOUT_MS}ms for ${url}`);
      } else {
        lastError = err instanceof Error ? err : new Error(msg);
      }
      console.warn(`[fetch] Attempt ${attempt}/${MAX_RETRIES} — ${lastError.message}`);
      if (attempt < MAX_RETRIES) await sleep(RETRY_BACKOFF_MS * attempt);
    }
  }
  throw lastError ?? new Error(`Failed to fetch ${url}`);
}

async function fetchHtml(url: string): Promise<cheerio.CheerioAPI> {
  const res = await rateLimitedFetch(url);
  const html = await res.text();
  return cheerio.load(html);
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

/** Convert "19.03.2026" → "2026-03-19" */
function parseEstonianDate(raw: string | undefined): string | null {
  if (!raw) return null;
  const m = raw.trim().match(/^(\d{2})\.(\d{2})\.(\d{4})$/);
  if (m) return `${m[3]}-${m[2]}-${m[1]}`;
  // Also accept ISO dates
  if (/^\d{4}-\d{2}-\d{2}$/.test(raw.trim())) return raw.trim();
  return null;
}

/** Extract CVE identifiers from text. */
function extractCves(text: string): string[] {
  const cves = text.match(/CVE-\d{4}-\d{4,}/g);
  return cves ? [...new Set(cves)] : [];
}

/** Build a stable reference slug from a URL path. */
function refFromPath(path: string, prefix: string): string {
  const slug = path
    .replace(/^\/blogi\//, "")
    .replace(/^\//, "")
    .replace(/\/$/, "");
  return `${prefix}-${slug}`.toUpperCase().slice(0, 120);
}

/** Truncate to N chars for summary. */
function summarise(text: string, maxLen = 400): string {
  const clean = text.replace(/\s+/g, " ").trim();
  if (clean.length <= maxLen) return clean;
  return clean.slice(0, maxLen - 1) + "\u2026";
}

/** Classify blog post category into advisory vs guidance. */
function classifyBlogCategory(category: string): "advisory" | "guidance" {
  const lower = category.toLowerCase();
  if (
    lower.includes("turvanorkus") ||
    lower.includes("turvanõrkus") ||
    lower.includes("hoiatus")
  ) {
    return "advisory";
  }
  return "guidance";
}

/** Map category string to a severity estimate for advisories. */
function estimateSeverity(title: string, body: string): string | null {
  const combined = (title + " " + body).toLowerCase();
  if (combined.includes("kriitiline") || combined.includes("critical")) return "critical";
  if (combined.includes("kõrge") || combined.includes("high")) return "high";
  if (combined.includes("keskmine") || combined.includes("medium")) return "medium";
  if (combined.includes("madal") || combined.includes("low")) return "low";
  // Weekly vulnerability roundups are typically "high" level
  if (combined.includes("turvanõrkus") || combined.includes("turvanorkus")) return "high";
  return null;
}

/** Extract product names from weekly vulnerability article headings. */
function extractAffectedProducts(body: string): string[] {
  const products: string[] = [];
  // Weekly roundups use headings like "## Chrome", "## Microsoft", "## Apache" etc.
  const headingMatches = body.match(/^#{1,3}\s+(.+)$/gm);
  if (headingMatches) {
    for (const h of headingMatches) {
      const text = h.replace(/^#{1,3}\s+/, "").trim();
      // Skip generic headings
      if (
        text.length > 2 &&
        text.length < 80 &&
        !text.toLowerCase().includes("olulisemad") &&
        !text.toLowerCase().includes("kokkuvõte") &&
        !text.toLowerCase().includes("lisalugemist") &&
        !text.toLowerCase().includes("nädal")
      ) {
        products.push(text);
      }
    }
  }
  return products;
}

/** Determine guidance type from content. */
function classifyGuidanceType(
  title: string,
  category: string,
): string {
  const t = (title + " " + category).toLowerCase();
  if (t.includes("juhend") || t.includes("guide")) return "guideline";
  if (t.includes("soovitus") || t.includes("recomm")) return "recommendation";
  if (t.includes("olukord") || t.includes("situation")) return "situation-report";
  if (t.includes("ülevaade") || t.includes("overview")) return "overview";
  if (t.includes("analüüs") || t.includes("analysis")) return "analysis";
  if (t.includes("nõuanne") || t.includes("advice")) return "recommendation";
  return "article";
}

/** Determine guidance series from URL or category. */
function classifyGuidanceSeries(url: string, category: string): string {
  if (url.includes("olukord-kuberruumis")) return "olukord-kuberruumis";
  if (url.includes("turvanorkus")) return "turvanorkused";
  if (url.includes("kuberuudised")) return "kuberuudised";
  if (url.includes("tehisintellekt")) return "tehisintellekt";
  const c = category.toLowerCase();
  if (c.includes("küberturvalisus") || c.includes("kuberturvalisus")) return "CERT-EE";
  return "RIA-blogi";
}

// ---------------------------------------------------------------------------
// Parsed record types
// ---------------------------------------------------------------------------

interface BlogEntry {
  url: string;
  title: string;
  date: string | null;
  category: string;
}

interface ParsedAdvisory {
  reference: string;
  title: string;
  date: string | null;
  severity: string | null;
  affected_products: string | null;
  summary: string;
  full_text: string;
  cve_references: string | null;
}

interface ParsedGuidance {
  reference: string;
  title: string;
  title_en: string | null;
  date: string | null;
  type: string;
  series: string;
  summary: string;
  full_text: string;
  topics: string | null;
  status: string;
}

// ---------------------------------------------------------------------------
// Phase 1 — Crawl blog listing pages
// ---------------------------------------------------------------------------

async function crawlBlogListing(): Promise<BlogEntry[]> {
  const entries: BlogEntry[] = [];
  let page = 0;

  console.log(`\n[blog] Crawling blog listing (max ${MAX_PAGES} pages) ...`);

  while (page < MAX_PAGES) {
    const url = page === 0 ? BLOG_LISTING : `${BLOG_LISTING}?page=${page}`;
    console.log(`[blog] Fetching page ${page}: ${url}`);

    let $: cheerio.CheerioAPI;
    try {
      $ = await fetchHtml(url);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`[blog] Failed to fetch page ${page}: ${msg}`);
      break;
    }

    const countBefore = entries.length;

    // RIA blog uses article/teaser elements. The listing contains links
    // with post titles, dates, and category labels. We look for the common
    // Drupal patterns used by ria.ee.
    $("article, .views-row, .node--type-blog, .view-content .views-row").each(
      (_i, el) => {
        const $el = $(el);

        // Title & link — look for the first heading link
        const $link =
          $el.find("h2 a, h3 a, .field--name-title a, .node__title a").first();
        if (!$link.length) return;

        const href = $link.attr("href");
        if (!href) return;

        const title = $link.text().trim();
        if (!title) return;

        const fullUrl = href.startsWith("http") ? href : `${BASE_URL}${href}`;

        // Date — look for <time> element or date field
        const $time = $el.find("time, .field--name-created, .node__date").first();
        const dateRaw =
          $time.attr("datetime")?.slice(0, 10) ??
          parseEstonianDate($time.text().trim()) ??
          null;

        // Category — look for taxonomy/tag field
        const $cat = $el
          .find(
            ".field--name-field-blog-category, .node__category, .field--name-field-category, .tag",
          )
          .first();
        const category = $cat.text().trim() || "Küberturvalisus";

        entries.push({ url: fullUrl, title, date: dateRaw, category });
      },
    );

    // Fallback: if the Drupal selectors did not match, try plain link parsing
    // on the page. The ria.ee blog renders post teasers as linked blocks.
    if (entries.length === countBefore) {
      $('a[href^="/blogi/"]').each((_i, el) => {
        const href = $(el).attr("href")!;
        const title = $(el).text().trim();
        if (
          !title ||
          title.length < 10 ||
          href === "/blogi" ||
          href === "/blogi/"
        )
          return;
        // Avoid duplicate links on same page
        const fullUrl = `${BASE_URL}${href}`;
        if (entries.some((e) => e.url === fullUrl)) return;

        // Try to find a sibling/parent date
        const parent = $(el).parent();
        const timeEl = parent.find("time").first();
        const dateRaw =
          timeEl.attr("datetime")?.slice(0, 10) ??
          parseEstonianDate(timeEl.text().trim()) ??
          null;

        entries.push({
          url: fullUrl,
          title,
          date: dateRaw,
          category: "Küberturvalisus",
        });
      });
    }

    // Pagination: check for "next page" link
    const hasNext =
      $('a[rel="next"], .pager__item--next a, a[title*="järgmis"]').length > 0;

    const added = entries.length - countBefore;
    console.log(`[blog] Page ${page}: found ${added} posts`);

    if (!hasNext || added === 0) {
      console.log(`[blog] No more pages.`);
      break;
    }

    page++;
  }

  // Deduplicate by URL
  const seen = new Set<string>();
  const unique = entries.filter((e) => {
    if (seen.has(e.url)) return false;
    seen.add(e.url);
    return true;
  });

  console.log(`[blog] Total unique blog entries: ${unique.length}`);
  return unique;
}

// ---------------------------------------------------------------------------
// Phase 2 — Crawl monthly situation reports listing
// ---------------------------------------------------------------------------

interface SituationReportLink {
  url: string;
  title: string;
  date: string | null;
}

async function crawlSituationReports(): Promise<SituationReportLink[]> {
  console.log(`\n[situation] Crawling situation reports listing ...`);

  let $: cheerio.CheerioAPI;
  try {
    $ = await fetchHtml(SITUATION_REPORTS);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.error(`[situation] Failed to fetch listing: ${msg}`);
    return [];
  }

  const reports: SituationReportLink[] = [];

  // The page lists links to monthly reports: /olukord-kuberruumis-{month}-{year}
  $("a").each((_i, el) => {
    const href = $(el).attr("href");
    if (!href) return;
    if (
      !href.includes("olukord-kuberruumis-") &&
      !href.includes("situation-cyberspace-")
    )
      return;
    // Skip PDF links — we want the HTML report pages
    if (href.endsWith(".pdf")) return;

    const title = $(el).text().trim();
    if (!title || title.length < 5) return;

    const fullUrl = href.startsWith("http") ? href : `${BASE_URL}${href}`;
    if (reports.some((r) => r.url === fullUrl)) return;

    reports.push({ url: fullUrl, title, date: null });
  });

  console.log(`[situation] Found ${reports.length} situation report links`);
  return reports;
}

// ---------------------------------------------------------------------------
// Phase 3 — Fetch individual post/report content
// ---------------------------------------------------------------------------

interface ArticleContent {
  title: string;
  body: string;
  date: string | null;
  category: string;
}

async function fetchArticle(
  url: string,
  fallbackTitle: string,
  fallbackDate: string | null,
  fallbackCategory: string,
): Promise<ArticleContent | null> {
  let $: cheerio.CheerioAPI;
  try {
    $ = await fetchHtml(url);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[article] Failed to fetch ${url}: ${msg}`);
    return null;
  }

  // Title: use <h1> or og:title
  const title =
    $("h1.page-title, h1.node__title, h1").first().text().trim() ||
    $('meta[property="og:title"]').attr("content")?.trim() ||
    fallbackTitle;

  // Date: <time> in article header, or meta
  const timeEl = $(
    "article time, .field--name-created time, .node__date time, time",
  ).first();
  const date =
    timeEl.attr("datetime")?.slice(0, 10) ??
    parseEstonianDate(timeEl.text().trim()) ??
    $('meta[property="article:published_time"]')
      ?.attr("content")
      ?.slice(0, 10) ??
    fallbackDate;

  // Category
  const catEl = $(
    ".field--name-field-blog-category, .node__category, .field--name-field-category",
  ).first();
  const category = catEl.text().trim() || fallbackCategory;

  // Body text — get the main content area
  const bodyEl = $(
    ".field--name-body, .node__content .field--type-text-with-summary, article .field--name-body, .layout-content .body, .text-formatted",
  ).first();

  let body: string;
  if (bodyEl.length) {
    // Convert to semi-structured text preserving headings
    body = extractStructuredText(bodyEl, $);
  } else {
    // Fallback: grab article or main content
    const mainEl = $("article, main, .layout-content").first();
    body = mainEl.length
      ? extractStructuredText(mainEl, $)
      : $("body").text().replace(/\s+/g, " ").trim();
  }

  if (!body || body.length < 50) {
    console.warn(`[article] Skipping ${url} — body too short (${body.length} chars)`);
    return null;
  }

  return { title, body, date, category };
}

/** Convert HTML element to text preserving heading structure as markdown-like markers. */
function extractStructuredText(
  el: cheerio.Cheerio<cheerio.Element>,
  $: cheerio.CheerioAPI,
): string {
  const parts: string[] = [];

  el.find("h1, h2, h3, h4, h5, h6, p, li, blockquote, td, th, figcaption")
    .each((_i, child) => {
      const tag = (child as cheerio.Element).tagName?.toLowerCase() ?? "";
      const text = $(child).text().replace(/\s+/g, " ").trim();
      if (!text) return;

      if (tag.startsWith("h")) {
        const level = parseInt(tag[1], 10);
        parts.push(`${"#".repeat(level)} ${text}`);
      } else if (tag === "li") {
        parts.push(`- ${text}`);
      } else {
        parts.push(text);
      }
    });

  if (parts.length === 0) {
    return el.text().replace(/\s+/g, " ").trim();
  }

  return parts.join("\n\n");
}

// ---------------------------------------------------------------------------
// Phase 4 — Crawl guidance pages (recommendations for organisations / users)
// ---------------------------------------------------------------------------

interface GuidanceLink {
  url: string;
  title: string;
}

async function crawlGuidanceLinks(): Promise<GuidanceLink[]> {
  console.log(`\n[guidance] Crawling guidance pages ...`);

  const links: GuidanceLink[] = [];

  for (const pageUrl of [GUIDANCE_ORGS, GUIDANCE_USERS]) {
    let $: cheerio.CheerioAPI;
    try {
      $ = await fetchHtml(pageUrl);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`[guidance] Failed to fetch ${pageUrl}: ${msg}`);
      continue;
    }

    // Guidance pages contain links to sub-pages and PDF downloads.
    // We collect sub-page links (HTML pages with guidance content).
    $("a").each((_i, el) => {
      const href = $(el).attr("href");
      if (!href) return;
      // Only follow internal ria.ee links (guidance pages, not PDFs)
      if (href.endsWith(".pdf")) return;
      if (
        !href.includes("kuberturbe-nouanded") &&
        !href.includes("kuberturvalisus") &&
        !href.includes("nouanded")
      )
        return;
      // Skip anchors and external
      if (href.startsWith("#")) return;

      const title = $(el).text().trim();
      if (!title || title.length < 5) return;

      const fullUrl = href.startsWith("http") ? href : `${BASE_URL}${href}`;
      // Avoid listing pages themselves
      if (fullUrl === pageUrl) return;
      if (links.some((l) => l.url === fullUrl)) return;

      links.push({ url: fullUrl, title });
    });
  }

  console.log(`[guidance] Found ${links.length} guidance page links`);
  return links;
}

// ---------------------------------------------------------------------------
// Database insertion
// ---------------------------------------------------------------------------

function insertAdvisory(db: Database.Database, a: ParsedAdvisory): boolean {
  try {
    db.prepare(
      `INSERT OR IGNORE INTO advisories
       (reference, title, date, severity, affected_products, summary, full_text, cve_references)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      a.reference,
      a.title,
      a.date,
      a.severity,
      a.affected_products,
      a.summary,
      a.full_text,
      a.cve_references,
    );
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[db] Advisory insert failed for ${a.reference}: ${msg}`);
    return false;
  }
}

function insertGuidance(db: Database.Database, g: ParsedGuidance): boolean {
  try {
    db.prepare(
      `INSERT OR IGNORE INTO guidance
       (reference, title, title_en, date, type, series, summary, full_text, topics, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      g.reference,
      g.title,
      g.title_en,
      g.date,
      g.type,
      g.series,
      g.summary,
      g.full_text,
      g.topics,
      g.status,
    );
    return true;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.warn(`[db] Guidance insert failed for ${g.reference}: ${msg}`);
    return false;
  }
}

function referenceExists(db: Database.Database, table: string, reference: string): boolean {
  const row = db
    .prepare(`SELECT 1 FROM ${table} WHERE reference = ? LIMIT 1`)
    .get(reference) as { 1: number } | undefined;
  return row !== undefined;
}

// ---------------------------------------------------------------------------
// Counters
// ---------------------------------------------------------------------------

interface Stats {
  blogEntriesFetched: number;
  situationReportsFetched: number;
  guidancePagesFetched: number;
  advisoriesInserted: number;
  guidanceInserted: number;
  skippedResume: number;
  skippedShort: number;
  errors: number;
}

function printStats(stats: Stats): void {
  console.log("\n--- Ingestion Summary ---");
  console.log(`Blog entries fetched:        ${stats.blogEntriesFetched}`);
  console.log(`Situation reports fetched:    ${stats.situationReportsFetched}`);
  console.log(`Guidance pages fetched:       ${stats.guidancePagesFetched}`);
  console.log(`Advisories inserted:         ${stats.advisoriesInserted}`);
  console.log(`Guidance inserted:           ${stats.guidanceInserted}`);
  console.log(`Skipped (resume):            ${stats.skippedResume}`);
  console.log(`Skipped (too short):         ${stats.skippedShort}`);
  console.log(`Errors:                      ${stats.errors}`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main(): Promise<void> {
  console.log("=== CERT-EE / RIA Ingestion Crawler ===");
  console.log(`Database: ${DB_PATH}`);
  console.log(
    `Flags: resume=${FLAG_RESUME} dry-run=${FLAG_DRY_RUN} force=${FLAG_FORCE} max-pages=${MAX_PAGES}`,
  );
  console.log(`Rate limit: ${RATE_LIMIT_MS}ms between requests`);
  console.log();

  const db = FLAG_DRY_RUN ? null : openDb();

  const stats: Stats = {
    blogEntriesFetched: 0,
    situationReportsFetched: 0,
    guidancePagesFetched: 0,
    advisoriesInserted: 0,
    guidanceInserted: 0,
    skippedResume: 0,
    skippedShort: 0,
    errors: 0,
  };

  // ── Step 1: Crawl blog listing ──────────────────────────────────────────

  const blogEntries = await crawlBlogListing();
  stats.blogEntriesFetched = blogEntries.length;

  for (const entry of blogEntries) {
    const classification = classifyBlogCategory(entry.category);
    const reference =
      classification === "advisory"
        ? refFromPath(new URL(entry.url).pathname, "CERT-EE-ADV")
        : refFromPath(new URL(entry.url).pathname, "RIA-BLOG");

    // Resume check
    if (FLAG_RESUME && db) {
      const table = classification === "advisory" ? "advisories" : "guidance";
      if (referenceExists(db, table, reference)) {
        stats.skippedResume++;
        continue;
      }
    }

    const article = await fetchArticle(
      entry.url,
      entry.title,
      entry.date,
      entry.category,
    );
    if (!article) {
      stats.skippedShort++;
      continue;
    }

    if (classification === "advisory") {
      const cves = extractCves(article.body);
      const products = extractAffectedProducts(article.body);
      const parsed: ParsedAdvisory = {
        reference,
        title: article.title,
        date: article.date,
        severity: estimateSeverity(article.title, article.body),
        affected_products: products.length > 0 ? JSON.stringify(products) : null,
        summary: summarise(article.body),
        full_text: article.body,
        cve_references: cves.length > 0 ? JSON.stringify(cves) : null,
      };

      if (FLAG_DRY_RUN) {
        console.log(`[dry-run] ADVISORY: ${parsed.reference} | ${parsed.title}`);
        console.log(
          `          date=${parsed.date} severity=${parsed.severity} cves=${cves.length} products=${products.length}`,
        );
      } else if (db && insertAdvisory(db, parsed)) {
        stats.advisoriesInserted++;
      }
    } else {
      const parsed: ParsedGuidance = {
        reference,
        title: article.title,
        title_en: null,
        date: article.date,
        type: classifyGuidanceType(article.title, article.category),
        series: classifyGuidanceSeries(entry.url, article.category),
        summary: summarise(article.body),
        full_text: article.body,
        topics: null,
        status: "current",
      };

      if (FLAG_DRY_RUN) {
        console.log(`[dry-run] GUIDANCE: ${parsed.reference} | ${parsed.title}`);
        console.log(`          date=${parsed.date} type=${parsed.type} series=${parsed.series}`);
      } else if (db && insertGuidance(db, parsed)) {
        stats.guidanceInserted++;
      }
    }
  }

  // ── Step 2: Crawl situation reports ─────────────────────────────────────

  const situationLinks = await crawlSituationReports();

  for (const link of situationLinks) {
    const reference = refFromPath(
      new URL(link.url).pathname,
      "RIA-SITUATION",
    );

    if (FLAG_RESUME && db && referenceExists(db, "guidance", reference)) {
      stats.skippedResume++;
      continue;
    }

    const article = await fetchArticle(link.url, link.title, link.date, "Olukord kuberruumis");
    if (!article) {
      stats.skippedShort++;
      continue;
    }
    stats.situationReportsFetched++;

    const parsed: ParsedGuidance = {
      reference,
      title: article.title,
      title_en: null,
      date: article.date,
      type: "situation-report",
      series: "olukord-kuberruumis",
      summary: summarise(article.body),
      full_text: article.body,
      topics: JSON.stringify(["olukord kuberruumis", "kuberturvalisus", "CERT-EE"]),
      status: "current",
    };

    if (FLAG_DRY_RUN) {
      console.log(`[dry-run] SITUATION: ${parsed.reference} | ${parsed.title}`);
      console.log(`          date=${parsed.date}`);
    } else if (db && insertGuidance(db, parsed)) {
      stats.guidanceInserted++;
    }
  }

  // ── Step 3: Crawl guidance pages ────────────────────────────────────────

  const guidanceLinks = await crawlGuidanceLinks();

  for (const link of guidanceLinks) {
    const reference = refFromPath(
      new URL(link.url).pathname,
      "RIA-GUIDE",
    );

    if (FLAG_RESUME && db && referenceExists(db, "guidance", reference)) {
      stats.skippedResume++;
      continue;
    }

    const article = await fetchArticle(link.url, link.title, null, "Juhend");
    if (!article) {
      stats.skippedShort++;
      continue;
    }
    stats.guidancePagesFetched++;

    const parsed: ParsedGuidance = {
      reference,
      title: article.title,
      title_en: null,
      date: article.date,
      type: classifyGuidanceType(article.title, "Juhend"),
      series: "RIA-juhend",
      summary: summarise(article.body),
      full_text: article.body,
      topics: JSON.stringify(["kuberturvalisus", "juhend", "RIA"]),
      status: "current",
    };

    if (FLAG_DRY_RUN) {
      console.log(`[dry-run] GUIDE: ${parsed.reference} | ${parsed.title}`);
      console.log(`          date=${parsed.date} type=${parsed.type}`);
    } else if (db && insertGuidance(db, parsed)) {
      stats.guidanceInserted++;
    }
  }

  // ── Step 4: Upsert frameworks ───────────────────────────────────────────

  if (!FLAG_DRY_RUN && db) {
    const frameworkDefs = [
      {
        id: "iske",
        name: "ISKE \u2014 Infosusteemide kolmeastmeline etalonturbe susteem",
        name_en: "ISKE \u2014 Three-level IT Baseline Security System",
        description:
          "Eesti riiklike infosusteemide kohustuslik turvalisuse raamistik. Pohil BSI IT-Grundschutz metoodikal. Klassid: L (madal), M (keskmine), H (korge). Koik avaliku sektori asutused peavad ISKE-d rakendama.",
      },
      {
        id: "e-its",
        name: "E-ITS \u2014 Eesti infoturbestandard",
        name_en: "E-ITS \u2014 Estonian Information Security Standard",
        description:
          "Alates 2023 asendab ISKE-d. Eesti infoturbestandard avaliku sektori infosusteemide turbe tagamiseks. Pohineb ISO 27001 ja BSI standarditel.",
      },
      {
        id: "nis2-ee",
        name: "NIS2 rakendamine Eestis",
        name_en: "NIS2 Implementation in Estonia",
        description:
          "Eesti NIS2 direktiivi rakendus. Kuberturvalisuse seaduse muudatused, oluliste ja tahtsate uksuste kohustused, intsidentide aruandlus.",
      },
      {
        id: "cert-ee-guidance",
        name: "CERT-EE juhendid",
        name_en: "CERT-EE Technical Guidance",
        description:
          "CERT-EE tehniline juhendmaterjal: intsidentide kasitlemine, ohuluureteave, haavatavuste avalikustamine, kuberturvalisuse parimad praktikad.",
      },
      {
        id: "kuberturvalisuse-seadus",
        name: "Kuberturvalisuse seadus",
        name_en: "Cybersecurity Act (Estonia)",
        description:
          "Eesti kuberturvalisuse seadus (KubTS). Kehtestab vorgu- ja infosüsteemide turvalisuse nouded, intsidentidest teavitamise kohustuse ja jarelevalve korra.",
      },
    ];

    const insF = db.prepare(
      "INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, 0)",
    );
    for (const f of frameworkDefs) {
      insF.run(f.id, f.name, f.name_en, f.description);
    }

    // Update document counts based on actual data
    db.exec(`
      UPDATE frameworks SET document_count = (
        SELECT count(*) FROM guidance WHERE series = frameworks.id
          OR (frameworks.id = 'cert-ee-guidance' AND series = 'CERT-EE')
          OR (frameworks.id = 'iske' AND series = 'ISKE')
          OR (frameworks.id = 'nis2-ee' AND series = 'NIS2')
      )
    `);

    console.log(`\n[db] Frameworks upserted.`);
  }

  // ── Summary ─────────────────────────────────────────────────────────────

  if (db) {
    const gCnt = (
      db.prepare("SELECT count(*) as cnt FROM guidance").get() as {
        cnt: number;
      }
    ).cnt;
    const aCnt = (
      db.prepare("SELECT count(*) as cnt FROM advisories").get() as {
        cnt: number;
      }
    ).cnt;
    const fCnt = (
      db.prepare("SELECT count(*) as cnt FROM frameworks").get() as {
        cnt: number;
      }
    ).cnt;

    console.log(`\n[db] Database totals: ${fCnt} frameworks, ${gCnt} guidance, ${aCnt} advisories`);
    db.close();
  }

  printStats(stats);
  console.log("\nDone.");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
