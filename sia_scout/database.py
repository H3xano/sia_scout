# FILE: sia_scout/database.py

import logging
import aiosqlite

logger = logging.getLogger(__name__)


async def initialize_database(db_path):
    """Creates the necessary tables in the database if they don't exist."""
    async with aiosqlite.connect(db_path) as db:
        # Table for individual threat listings (the "hits")
        await db.execute("""
                         CREATE TABLE IF NOT EXISTS hits
                         (
                             dataset
                             TEXT,
                             ipaddress
                             TEXT,
                             asn
                             INTEGER,
                             cc
                             TEXT,
                             listed
                             INTEGER,
                             seen
                             INTEGER,
                             valid_until
                             INTEGER,
                             rule
                             TEXT,
                             botname
                             TEXT,
                             botname_malpedia
                             TEXT,
                             dstport
                             INTEGER,
                             heuristic
                             TEXT,
                             lat
                             REAL,
                             lon
                             REAL,
                             protocol
                             TEXT,
                             srcip
                             TEXT,
                             domain
                             TEXT,
                             helo
                             TEXT,
                             detection
                             TEXT, -- <<< THIS WAS THE MISSING COLUMN
                             PRIMARY
                             KEY
                         (
                             ipaddress,
                             listed,
                             rule
                         )
                             )
                         """)

        # Table to log which /24 CIDRs have been scanned in this run (our cache)
        await db.execute("""
                         CREATE TABLE IF NOT EXISTS scanned_cidrs
                         (
                             cidr
                             TEXT
                             PRIMARY
                             KEY,
                             scanned_at
                             INTEGER
                         )
                         """)
        await db.commit()
    logger.info(f"Database initialized at {db_path}")


async def check_if_scanned(db, cidr_str):
    """Checks if a CIDR has already been logged as scanned in the database."""
    async with db.execute("SELECT 1 FROM scanned_cidrs WHERE cidr = ?", (cidr_str,)) as cursor:
        return await cursor.fetchone() is not None


async def insert_hits(db, hits):
    """Inserts a list of hit records into the database."""
    if not hits:
        return 0

    await db.executemany("""
                         INSERT
                         OR IGNORE INTO hits (
            dataset, ipaddress, asn, cc, listed, seen, valid_until, rule,
            botname, botname_malpedia, dstport, heuristic, lat, lon,
            protocol, srcip, domain, helo, detection
        ) VALUES (
            :dataset, :ipaddress, :asn, :cc, :listed, :seen, :valid_until, :rule,
            :botname, :botname_malpedia, :dstport, :heuristic, :lat, :lon,
            :protocol, :srcip, :domain, :helo, :detection
        )
                         """, hits)
    await db.commit()
    return len(hits)


async def mark_as_scanned(db, cidr_str, timestamp):
    """Marks a CIDR as scanned in the log table."""
    await db.execute(
        "INSERT INTO scanned_cidrs (cidr, scanned_at) VALUES (?, ?)",
        (cidr_str, timestamp)
    )
    await db.commit()