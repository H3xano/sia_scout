# FILE: sia_scout/analyzer.py

import logging
import pandas as pd
import aiosqlite

logger = logging.getLogger(__name__)


class Analyzer:
    def __init__(self, db_path):
        self.db_path = db_path

    async def generate_summary_report(self):
        """Connects to the DB, analyzes the 'hits' table, and prints a report."""
        logger.info(f"Connecting to database at {self.db_path} to generate report...")

        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute("SELECT * FROM hits") as cursor:
                    df = await cursor.execute_fetchall_pandas()
        except Exception as e:
            logger.error(f"Could not read from database: {e}")
            if "no such table" in str(e):
                logger.error("The 'hits' table does not exist. Run the 'collect' action first.")
            return

        if df.empty:
            logger.warning("No listings found in the database. Cannot generate a report.")
            return

        total_hits = len(df)
        unique_ips = df['ipaddress'].nunique()

        # --- Build the Report String ---
        report = "\n"
        report += "=================================================\n"
        report += "           SIA-Scout Threat Report\n"
        report += "=================================================\n"
        report += f"\nTotal Listings Found: {total_hits}"
        report += f"\nUnique Malicious IPs: {unique_ips}\n"
        report += "-------------------------------------------------\n"

        report += "\n[+] Top 10 Threat Detections:\n"
        if 'detection' in df.columns:
            report += df['detection'].value_counts().nlargest(10).to_string()
        else:
            report += "Detection data not available."
        report += "\n\n"

        report += "[+] Top 10 Botnet Families:\n"
        if 'botname' in df.columns:
            botnets = df[df['botname'].notna() & (df['botname'] != 'unknown')]
            if not botnets.empty:
                report += botnets['botname'].value_counts().nlargest(10).to_string()
            else:
                report += "No known botnet families found."
        else:
            report += "Botnet data not available."
        report += "\n\n"

        # --- NEW: Top 10 C2 / Malicious Domains ---
        report += "[+] Top 10 C2 / Malicious Domains:\n"
        if 'domain' in df.columns:
            # Filter for rows that are likely C2s (in XBL dataset) and have a valid domain
            c2_domains = df[
                (df['dataset'] == 'XBL') &
                (df['domain'].notna()) &
                (df['domain'] != 'unknown')
                ]
            if not c2_domains.empty:
                report += c2_domains['domain'].value_counts().nlargest(10).to_string()
            else:
                report += "No C2 domains found in the XBL dataset."
        else:
            report += "Domain data not available."
        report += "\n\n"

        # --- NEW: Top 10 Detection Heuristics ---
        report += "[+] Top 10 Detection Heuristics:\n"
        if 'heuristic' in df.columns:
            heuristics = df[df['heuristic'].notna()]
            if not heuristics.empty:
                report += heuristics['heuristic'].value_counts().nlargest(10).to_string()
            else:
                report += "No heuristic data found."
        else:
            report += "Heuristic data not available."
        report += "\n\n"

        report += "[+] Top 10 Noisiest ASNs (by hit count):\n"
        if 'asn' in df.columns:
            report += df['asn'].astype(str).value_counts().nlargest(10).to_string()
        else:
            report += "ASN data not available."
        report += "\n\n"

        report += "=================== End of Report ===================\n"

        print(report)


async def _fetchall_pandas(self):
    """A helper to monkey-patch aiosqlite cursor to return a pandas DataFrame."""
    columns = [x[0] for x in self.description]
    data = await self.fetchall()
    return pd.DataFrame(data, columns=columns)


aiosqlite.Cursor.execute_fetchall_pandas = _fetchall_pandas