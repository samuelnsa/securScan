/**
 * Gestion de la base de données SQLite locale pour SecurScan
 */
import { DatabaseSync } from 'node:sqlite';
import path from 'node:path';
import fs from 'node:fs';

const DB_DIR = path.resolve(process.cwd(), 'data');
if (!fs.existsSync(DB_DIR)) {
  fs.mkdirSync(DB_DIR, { recursive: true });
}

const dbPath = path.join(DB_DIR, 'securscan.db');
export const db = new DatabaseSync(dbPath);

// Initialisation des schémas SQL
export function initDatabase() {
  db.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS sites (
      id TEXT PRIMARY KEY,
      hostname TEXT UNIQUE NOT NULL,
      target_url TEXT NOT NULL,
      created_at TEXT NOT NULL,
      last_scanned_at TEXT,
      latest_score INTEGER DEFAULT 0,
      latest_grade TEXT DEFAULT 'F'
    );

    CREATE TABLE IF NOT EXISTS scans (
      id TEXT PRIMARY KEY,
      site_id TEXT NOT NULL,
      score INTEGER NOT NULL,
      grade TEXT NOT NULL,
      verdict TEXT,
      duration_ms INTEGER,
      timestamp TEXT NOT NULL,
      passed_count INTEGER DEFAULT 0,
      failed_count INTEGER DEFAULT 0,
      regressions_count INTEGER DEFAULT 0,
      raw_json TEXT NOT NULL,
      FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS vulnerabilities (
      id TEXT PRIMARY KEY,
      site_id TEXT NOT NULL,
      scan_id TEXT NOT NULL,
      code TEXT NOT NULL,
      title TEXT NOT NULL,
      severity TEXT NOT NULL,
      cwe TEXT,
      cwe_title TEXT,
      description TEXT,
      remediation TEXT,
      snippet TEXT,
      status TEXT DEFAULT 'OPEN',
      first_seen_at TEXT NOT NULL,
      last_seen_at TEXT NOT NULL,
      resolved_at TEXT,
      FOREIGN KEY (site_id) REFERENCES sites (id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_scans_site_id ON scans(site_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_site_id ON vulnerabilities(site_id);
    CREATE INDEX IF NOT EXISTS idx_vulns_status ON vulnerabilities(status);
  `);
}

// Initialiser immédiatement à l'import
initDatabase();
