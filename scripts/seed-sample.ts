/**
 * Seed the RIA/CERT-EE database with sample guidance documents, advisories,
 * and frameworks for testing.
 *
 * Usage:
 *   npx tsx scripts/seed-sample.ts
 *   npx tsx scripts/seed-sample.ts --force   # drop and recreate
 */

import Database from "better-sqlite3";
import { existsSync, mkdirSync, unlinkSync } from "node:fs";
import { dirname } from "node:path";
import { SCHEMA_SQL } from "../src/db.js";

const DB_PATH = process.env["RIA_DB_PATH"] ?? "data/ria.db";
const force = process.argv.includes("--force");

const dir = dirname(DB_PATH);
if (!existsSync(dir)) { mkdirSync(dir, { recursive: true }); }
if (force && existsSync(DB_PATH)) { unlinkSync(DB_PATH); console.log(`Deleted ${DB_PATH}`); }

const db = new Database(DB_PATH);
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(SCHEMA_SQL);
console.log(`Database initialised at ${DB_PATH}`);

// --- Frameworks ---
const frameworks = [
  { id: "iske", name: "ISKE — Infosüsteemide kolmeastmeline etalonturbe süsteem", name_en: "ISKE — Three-level IT Baseline Security System", description: "Estonia mandatory security framework for state information systems. Defines security classes L (low), M (medium), H (high). All public sector entities must classify systems and implement ISKE requirements.", document_count: 3 },
  { id: "nis2-ee", name: "NIS2 rakendamine Eestis", name_en: "NIS2 Implementation in Estonia", description: "Estonia's implementation of EU NIS2 Directive. Covers essential and important entity obligations, incident reporting, minimum cybersecurity measures. Transposed via Kuberturvalisuse seadus amendments.", document_count: 2 },
  { id: "cert-ee-guidance", name: "CERT-EE Juhendid", name_en: "CERT-EE Technical Guidance", description: "CERT-EE technical guidance covering incident response, threat intelligence, vulnerability disclosure, and cybersecurity best practices.", document_count: 4 },
];
const insF = db.prepare("INSERT OR IGNORE INTO frameworks (id, name, name_en, description, document_count) VALUES (?, ?, ?, ?, ?)");
for (const f of frameworks) insF.run(f.id, f.name, f.name_en, f.description, f.document_count);
console.log(`Inserted ${frameworks.length} frameworks`);

// --- Guidance ---
const guidance = [
  {
    reference: "RIA-ISKE-2023", title: "ISKE rakendamise juhend 2023", title_en: "ISKE Implementation Guide 2023",
    date: "2023-01-15", type: "guideline", series: "ISKE",
    summary: "ISKE 2023 juhend kirjeldab klassifitseerimise metoodikat, turvameetmete valiku pohimotteid ja rakendamist avaliku sektori infosüsteemides.",
    full_text: "ISKE on Eesti riiklike infosüsteemide kohustuslik turvalisuse raamistik. Pohil Saksa BSI IT-Grundschutzi metoodikal, kohandatud Eesti avaliku sektori vajadustele. ISKE 2023 sisaldab: pilveturbe meetmete loimimine; NIS2 direktiivi nouete kajastamine; ISO 27001:2022 ja NIST SP 800-53 r5 standardite arvestamine. Klassifikatsioon: L-tase (madal) minimaalse mojuga süsteemidele; M-tase (keskmine) olulisi teenuseid mojutavatele; H-tase (korgeim) kriitilisele infrastruktuurile. Kõik riigiasutused klassifitseerivad oma infosüsteemid ja rakendavad vastavaid meetmeid.",
    topics: JSON.stringify(["ISKE", "turvaklass", "infosüsteem", "avalik sektor", "NIS2"]), status: "current",
  },
  {
    reference: "RIA-NIS2-2024", title: "NIS2 direktiivi rakendamise juhend Eestis", title_en: "NIS2 Directive Implementation Guide for Estonia",
    date: "2024-01-10", type: "directive", series: "NIS2",
    summary: "Juhend NIS2 direktiivi nouete rakendamiseks Eestis: oluliste ja tahtsamamate üksuste kohustused, intsidentide aruandlus, minimaalsed meetmed.",
    full_text: "NIS2 direktiiv (EL 2022/2555) kohustab liikmesriike tagama korgel yhisel kuberturvalisuse taseme. Eesti rakendas Kuberturvalisuse seaduse muudatuste kaudu (joustitid 2024 oktoobris). Kohaldamisala: 18 sektorit sh energia, transport, tervishoid, digitaristu. Intsidentide aruandlus: esmane teavitus 24h jooksul, loplik aruanne 72h. Trahvid: olulised üksused kuni 10 mln EUR voi 2% kaibest; tahtsamamad kuni 7 mln EUR voi 1,4%. RIA on peamine jarelevalveasutus.",
    topics: JSON.stringify(["NIS2", "kuberturvalisus", "intsidentide aruandlus", "riskijuhtimine"]), status: "current",
  },
  {
    reference: "CERT-EE-TG-2023-01", title: "Intsidentide käsitlemise juhend organisatsioonidele", title_en: "Incident Response Guidance for Organisations",
    date: "2023-06-01", type: "guideline", series: "RIA-juhend",
    summary: "CERT-EE juhend intsidentide käsitlemise protsessile: tuvastamine, teavitamine, analyys, ohjeldamine ja taastumine.",
    full_text: "CERT-EE intsidentide käsitlemise juhend pakub struktureeritud metoodikat. Pohil NIST SP 800-61 ja ENISA soovitustel. Etapid: (1) Ettevalmistus — meeskond, kontaktid, taristu; (2) Tuvastamine ja analyys — SIEM, ohuluureteave; (3) Ohjeldamine — leviku piiramine, isolatsioon; (4) Likvideerimine — pahavara eemaldamine, haavatavuste sulgemine; (5) Taastumine — teenuste taastamine; (6) Järeltegevused — dokumenteerimine, soovitused. Teavitage: cert@cert.ee voi cert.ee veebis.",
    topics: JSON.stringify(["intsidentide käsitlemine", "CERT-EE", "kuberturvalisus"]), status: "current",
  },
  {
    reference: "CERT-EE-TG-2024-02", title: "Lunavararünnakute ennetamine ja käsitlemine", title_en: "Ransomware Prevention and Response",
    date: "2024-03-15", type: "recommendation", series: "RIA-juhend",
    summary: "CERT-EE soovitused lunavararünnakute ennetamiseks: varukoopiate haldus, sisevõrgu segmenteerimine, taasteplaanid.",
    full_text: "Lunavararünnakute arv kasvas 40% 2022-2023 perioodil. Ennetusmeetmed: (1) Varundamine — 3-2-1 reegel, koopiate testimine; (2) Sisevõrgu segmenteerimine — kriitiliste süsteemide eraldamine; (3) Juurdepääsuhaldus — minimaalsete oiguste pohimotet, MFA, PAM; (4) Tarkvaravärskendused — automaatne paikamine; (5) EDR ja SIEM lahendused. Rünnaku korral: arege makske lunaraha, isoleerige süsteemid, teavitage CERT-EE-d, dokumenteerige. RIA pakub tasuta tehnilist abi.",
    topics: JSON.stringify(["lunavara", "küberrunnak", "varundamine"]), status: "current",
  },
  {
    reference: "RIA-ISKE-2022", title: "ISKE rakendamise juhend 2022", title_en: "ISKE Implementation Guide 2022",
    date: "2022-01-10", type: "guideline", series: "ISKE",
    summary: "ISKE 2022 — eelmine versioon, asendatud 2023. aasta versiooniga.",
    full_text: "ISKE 2022 eelmine versioon. Sisaldas turvameetmeid ISO 27001:2013 ja NIST SP 800-53 r4 alusel. Lisa: kaugtoo turvalisus COVID-19 kogemuste pohjalal, pilveteenuste soovituste uuendus. Asendatud ISKE 2023-ga.",
    topics: JSON.stringify(["ISKE", "turvaklass"]), status: "superseded",
  },
];

const insG = db.prepare("INSERT OR IGNORE INTO guidance (reference, title, title_en, date, type, series, summary, full_text, topics, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
const insGAll = db.transaction(() => { for (const g of guidance) insG.run(g.reference, g.title, g.title_en, g.date, g.type, g.series, g.summary, g.full_text, g.topics, g.status); });
insGAll();
console.log(`Inserted ${guidance.length} guidance documents`);

// --- Advisories ---
const advisories = [
  {
    reference: "CERT-EE-2024-001", title: "Kriitiline haavatavus Ivanti Connect Secure VPN tarkvaras",
    date: "2024-01-10", severity: "critical",
    affected_products: JSON.stringify(["Ivanti Connect Secure", "Ivanti Policy Secure"]),
    summary: "CERT-EE teavitab kriitilisest nullpäeva haavatavusest Ivanti Connect Secure VPN tarkvaras, mis võimaldab autentimata kaugkäivitust.",
    full_text: "Kriitiline haavatavus (CVSS 10.0) Ivanti Connect Secure VPN tarkvaras. CVE-2024-21887 (käsuinjektsioon) koos CVE-2023-46805 (autentimise moondasoit) võimaldab autentimata kasituste taitmist. Aktiivselt kuritarvitatud Eesti organisatsioonide vastu. Meetmed: rakendage Ivanti leevendusmeetmed; kontrollige ühenduste logisid; eeldage kompromiteerimist; teavitage CERT-EE-d.",
    cve_references: JSON.stringify(["CVE-2024-21887", "CVE-2023-46805"]),
  },
  {
    reference: "CERT-EE-2023-015", title: "Phishing kampaania Eesti pangaklientide vastu",
    date: "2023-11-20", severity: "high",
    affected_products: JSON.stringify(["Smart-ID", "Mobiil-ID", "Pangaportaalid"]),
    summary: "CERT-EE hoiatab phishing kampaania eest, mis sihib Eesti pangaklientide Smart-ID ja Mobiil-ID volikirju.",
    full_text: "Koordineeritud phishing kampaania Eesti pangaklientide vastu. 450+ kaebust 48h jooksul, 12 phishing domeeni blokeeritud. Ründemeetodid: e-kirjad imiteerivad Swedbank, SEB, LHV, Coop teateid; kiireloomulisuse loomine; suunamine voitsitud sisselogimislehele. Kaitsemeetmed: kasutage panga ametlikku URL-i; arege klikkige linkidel; teavitage cert@cert.ee.",
    cve_references: null,
  },
  {
    reference: "CERT-EE-2024-008", title: "MOVEit Transfer kriitilised haavatavused",
    date: "2024-02-28", severity: "critical",
    affected_products: JSON.stringify(["Progress MOVEit Transfer", "MOVEit Cloud"]),
    summary: "Kriitilised SQL-injektsiooni haavatavused MOVEit Transfer'is, mida kuritarvitab lunavaragrupp Cl0p.",
    full_text: "CVE-2024-5806 ja CVE-2024-5805 võimaldavad SQL-injektsiooni kaudu autentimata juurdepääsu. Cl0p kuritarvitab MOVEit haavatavusi alates 2023. Mõjutatud: MOVEit Transfer < 2024.0.1, < 2023.1.5, < 2023.0.11. Meetmed: rakendage turvapaid viivitamatult; kontrollige logikirjeid SQL-päringute suhtes; piirake juurdepääs; teavitage andmelekke korral.",
    cve_references: JSON.stringify(["CVE-2024-5806", "CVE-2024-5805"]),
  },
];

const insA = db.prepare("INSERT OR IGNORE INTO advisories (reference, title, date, severity, affected_products, summary, full_text, cve_references) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
const insAAll = db.transaction(() => { for (const a of advisories) insA.run(a.reference, a.title, a.date, a.severity, a.affected_products, a.summary, a.full_text, a.cve_references); });
insAAll();
console.log(`Inserted ${advisories.length} advisories`);

const gCnt = (db.prepare("SELECT count(*) as cnt FROM guidance").get() as { cnt: number }).cnt;
const aCnt = (db.prepare("SELECT count(*) as cnt FROM advisories").get() as { cnt: number }).cnt;
const fCnt = (db.prepare("SELECT count(*) as cnt FROM frameworks").get() as { cnt: number }).cnt;
console.log(`\nSummary: ${fCnt} frameworks, ${gCnt} guidance, ${aCnt} advisories`);
console.log(`Done. Database ready at ${DB_PATH}`);
db.close();
