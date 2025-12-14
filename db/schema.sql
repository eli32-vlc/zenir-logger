CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE,
    target TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    link_id INTEGER NOT NULL,
    ip TEXT,
    user_agent TEXT,
    referer TEXT,
    screen_width INTEGER,
    screen_height INTEGER,
    device_pixel_ratio REAL,
    language TEXT,
    platform TEXT,
    fingerprint TEXT,
    fingerprint_details TEXT,
    timezone TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(link_id) REFERENCES links(id)
);
