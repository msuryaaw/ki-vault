-- KiVault SQLite In-Memory Database Schema v1
-- Defined per docs/database.md

PRAGMA foreign_keys = ON;

-- 1. Vault Metadata
CREATE TABLE IF NOT EXISTS vault_metadata (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 2. Platforms
CREATE TABLE IF NOT EXISTS platforms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    category TEXT,
    website TEXT,
    logo_id TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 3. Accounts
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    platform_id TEXT NOT NULL,
    display_name TEXT,
    username TEXT,
    email TEXT,
    password TEXT,
    url TEXT,
    notes TEXT,
    logo_id TEXT,
    is_favorite INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,

    FOREIGN KEY (platform_id)
        REFERENCES platforms(id)
        ON DELETE CASCADE
);

-- 4. Custom Fields
CREATE TABLE IF NOT EXISTS custom_fields (
    id TEXT PRIMARY KEY,
    account_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    field_value TEXT NOT NULL,
    field_type TEXT NOT NULL DEFAULT 'text',
    is_sensitive INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,

    FOREIGN KEY (account_id)
        REFERENCES accounts(id)
        ON DELETE CASCADE
);

-- 5. Tags
CREATE TABLE IF NOT EXISTS tags (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at INTEGER NOT NULL
);

-- 6. Account Tags
CREATE TABLE IF NOT EXISTS account_tags (
    account_id TEXT NOT NULL,
    tag_id TEXT NOT NULL,

    PRIMARY KEY (account_id, tag_id),

    FOREIGN KEY (account_id)
        REFERENCES accounts(id)
        ON DELETE CASCADE,

    FOREIGN KEY (tag_id)
        REFERENCES tags(id)
        ON DELETE CASCADE
);

-- 7. Logos
CREATE TABLE IF NOT EXISTS logos (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    image_data BLOB NOT NULL,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

-- 8. Vault Settings
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Indexes (§12 of database.md)
CREATE INDEX IF NOT EXISTS idx_accounts_platform
ON accounts(platform_id);

CREATE INDEX IF NOT EXISTS idx_accounts_favorite
ON accounts(is_favorite);

CREATE INDEX IF NOT EXISTS idx_accounts_display_name
ON accounts(display_name);

CREATE INDEX IF NOT EXISTS idx_accounts_username
ON accounts(username);

CREATE INDEX IF NOT EXISTS idx_accounts_email
ON accounts(email);

CREATE INDEX IF NOT EXISTS idx_custom_fields_account
ON custom_fields(account_id);

CREATE INDEX IF NOT EXISTS idx_account_tags_tag
ON account_tags(tag_id);
