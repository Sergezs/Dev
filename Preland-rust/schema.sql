-- Analytics D1 schema

CREATE TABLE IF NOT EXISTS visits (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    vid       TEXT NOT NULL DEFAULT '',
    t         INTEGER NOT NULL,
    h         TEXT NOT NULL DEFAULT '',
    co        TEXT NOT NULL DEFAULT '',
    ci        TEXT NOT NULL DEFAULT '',
    d         TEXT NOT NULL DEFAULT '',
    s         TEXT NOT NULL DEFAULT '',
    rf        TEXT NOT NULL DEFAULT '',
    fbclid    TEXT NOT NULL DEFAULT '',
    utm_c     TEXT NOT NULL DEFAULT '',
    utm_ct    TEXT NOT NULL DEFAULT '',
    ua        TEXT NOT NULL DEFAULT '',
    utm_as    TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS purchases (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    t         INTEGER NOT NULL,
    fbclid    TEXT NOT NULL DEFAULT '',
    amount    REAL NOT NULL DEFAULT 0,
    currency  TEXT NOT NULL DEFAULT 'USD',
    visit_t   INTEGER NOT NULL DEFAULT 0,
    ua        TEXT NOT NULL DEFAULT '',
    event_id  TEXT NOT NULL DEFAULT '',
    capi_ok   INTEGER NOT NULL DEFAULT 0,
    utm_c     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS tg_links (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    t         INTEGER NOT NULL,
    vid       TEXT NOT NULL UNIQUE,
    tg_id     INTEGER NOT NULL DEFAULT 0,
    tg_user   TEXT NOT NULL DEFAULT '',
    tg_name   TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS registrations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    t         INTEGER NOT NULL,
    fbclid    TEXT NOT NULL DEFAULT '',
    visit_t   INTEGER NOT NULL DEFAULT 0,
    ua        TEXT NOT NULL DEFAULT '',
    event_id  TEXT NOT NULL DEFAULT '',
    capi_ok   INTEGER NOT NULL DEFAULT 0,
    utm_c     TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS bot_users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER NOT NULL UNIQUE,
    username    TEXT NOT NULL DEFAULT '',
    start_param TEXT NOT NULL DEFAULT '',
    is_suspicious INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
);

CREATE TABLE IF NOT EXISTS bot_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER NOT NULL,
    event_name  TEXT NOT NULL,
    t           INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
);

CREATE TABLE IF NOT EXISTS bot_payments (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id INTEGER NOT NULL,
    amount      REAL NOT NULL DEFAULT 0,
    t           INTEGER NOT NULL DEFAULT (strftime('%s','now') * 1000)
);
