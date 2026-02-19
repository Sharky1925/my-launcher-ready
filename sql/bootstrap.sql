-- D1 bootstrap schema for Cloudflare-native Worker rewrite.

CREATE TABLE IF NOT EXISTS services (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  summary TEXT NOT NULL,
  display_order INTEGER NOT NULL DEFAULT 0,
  is_published INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  excerpt TEXT NOT NULL,
  body TEXT,
  is_published INTEGER NOT NULL DEFAULT 1,
  published_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE IF NOT EXISTS contact_submissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  subject TEXT,
  message TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quote_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ticket_number TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  phone TEXT,
  company TEXT,
  primary_service TEXT NOT NULL,
  budget TEXT,
  timeline TEXT,
  details TEXT NOT NULL,
  ip TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL
);

INSERT OR IGNORE INTO services (slug, title, summary, display_order, is_published) VALUES
  ('managed-it-services', 'Managed IT Services', '24/7 monitoring, endpoint management, and support operations.', 1, 1),
  ('cybersecurity', 'Cybersecurity', 'Identity controls, endpoint hardening, and practical security operations.', 2, 1),
  ('cloud-migration', 'Cloud Migration', 'Cloud adoption with phased migration plans and rollback safety.', 3, 1),
  ('computer-repair', 'Computer Repair', 'Hardware diagnostics, component replacement, and stabilization.', 4, 1);

INSERT OR IGNORE INTO posts (slug, title, excerpt, body, is_published) VALUES
  ('building-a-practical-security-baseline', 'Building a Practical Security Baseline', 'A pragmatic way to reduce incident risk in SMB environments.', 'Start with identity, endpoint inventory, and patch cadence.', 1),
  ('choosing-managed-services-vs-in-house-it', 'Managed Services vs In-House IT', 'How to decide based on cost, response time, and operational complexity.', 'Use your ticket load and SLA obligations as decision anchors.', 1);
