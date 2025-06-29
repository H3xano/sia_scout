# FILE: config.py

import os
from dotenv import load_dotenv

load_dotenv()

# --- Credentials ---
SIA_USERNAME = os.getenv("SIA_USERNAME")
SIA_PASSWORD = os.getenv("SIA_PASSWORD")

# --- API Configuration ---
API_BASE_URL = "https://api.spamhaus.org"
CONCURRENCY_LIMIT = 20

# --- CIDR Query Parameters ---
SIA_DATASET = "ALL"
SIA_MODE = "listed"
SIA_LIMIT = 2000

# --- History Configuration ---
# Default number of days to look back for historical scans.
# NOTE: The API has a 12-month limit, so 364 is a safe maximum.
HISTORY_LOOKBACK_DAYS = 364

# --- File Paths ---
os.makedirs("output", exist_ok=True)
DATABASE_FILE = "output/sia_scout.db"
LOG_FILE = "output/sia_scout.log"
TOKEN_FILE = "output/token.json"
TARGET_FILE = "targets/cidrs.txt"