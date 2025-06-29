# FILE: sia_scout/analyzer.py

import logging
import pandas as pd
import aiosqlite

logger = logging.getLogger(__name__)


# This helper function allows us to re-use the pandas compatibility patch
async def _fetchall_pandas(self):
    """A helper to monkey-patch aiosqlite cursor to return a pandas DataFrame."""
    columns = [x[0] for x in self.description]
    data = await self.fetchall()
    return pd.DataFrame(data, columns=columns)


aiosqlite.Cursor.execute_fetchall_pandas = _fetchall_pandas


class Analyzer:
    def __init__(self, db_path):
        self.db_path = db_path

    async def _load_dataframe(self, table_name="hits"):
        """Loads data from a specified table into a pandas DataFrame."""
        logger.info(f"Connecting to database to load data from table '{table_name}'...")
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(f"SELECT * FROM {table_name}") as cursor:
                    return await cursor.execute_fetchall_pandas()
        except Exception as e:
            logger.error(f"Could not read from table '{table_name}': {e}")
            if "no such table" in str(e):
                logger.error(f"The '{table_name}' table does not exist. Run a collection first.")
            return pd.DataFrame()

    async def _generate_report(self, df, report_title):
        """A generic report generator that works on any DataFrame."""
        if df.empty:
            logger.warning(f"No data available to generate {report_title}.")
            return

        total_hits = len(df)
        unique_ips = df['ipaddress'].nunique()

        report = f"\n=================================================\n"
        report += f"           {report_title}\n"
        report += "=================================================\n"
        report += f"\nTotal Listings Found: {total_hits}"
        report += f"\nUnique Malicious IPs: {unique_ips}\n"
        report += "-------------------------------------------------\n"

        # Top 10 Threat Detections
        report += "\n[+] Top 10 Threat Detections:\n"
        if 'detection' in df.columns:
            report += df['detection'].value_counts().nlargest(10).to_string()
        else:
            report += "Detection data not available."
        report += "\n\n"

        # Top 10 Botnet Families
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

        # Top 10 C2 / Malicious Domains
        report += "[+] Top 10 C2 / Malicious Domains:\n"
        if 'domain' in df.columns:
            c2s = df[(df['dataset'] == 'XBL') & df['domain'].notna() & (df['domain'] != 'unknown')]
            if not c2s.empty:
                report += c2s['domain'].value_counts().nlargest(10).to_string()
            else:
                report += "No C2 domains found in the XBL dataset."
        else:
            report += "Domain data not available."
        report += "\n\n"

        # Top 10 Detection Heuristics
        report += "[+] Top 10 Detection Heuristics:\n"
        if 'heuristic' in df.columns and df['heuristic'].notna().any():
            report += df['heuristic'].value_counts().nlargest(10).to_string()
        else:
            report += "Heuristic data not available."
        report += "\n\n"

        # Top 10 Noisiest ASNs
        report += "[+] Top 10 Noisiest ASNs (by hit count):\n"
        if 'asn' in df.columns:
            report += df['asn'].astype(str).value_counts().nlargest(10).to_string()
        else:
            report += "ASN data not available."
        report += "\n\n"

        report += "=================== End of Report ===================\n"
        print(report)

    async def generate_summary_report(self):
        """Analyzes the LIVE 'hits' table."""
        df = await self._load_dataframe(table_name="hits")
        await self._generate_report(df, "SIA-Scout Live Threat Report")

    async def generate_history_summary_report(self):
        """Analyzes the HISTORICAL 'history_hits' table."""
        df = await self._load_dataframe(table_name="history_hits")
        await self._generate_report(df, "SIA-Scout Historical Threat Report")