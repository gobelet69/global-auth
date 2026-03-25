CREATE TABLE IF NOT EXISTS user_integrations (
  username TEXT PRIMARY KEY,
  github_token TEXT,
  updated_at TEXT DEFAULT (datetime('now'))
);
