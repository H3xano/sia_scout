# FILE: sia_scout/visualizer.py

import logging
import pandas as pd
import aiosqlite
import matplotlib.pyplot as plt
import seaborn as sns
import os

try:
    from sia_scout.analyzer import _fetchall_pandas
    aiosqlite.Cursor.execute_fetchall_pandas = _fetchall_pandas
except ImportError:
    async def _fetchall_pandas(self):
        columns = [x[0] for x in self.description]
        data = await self.fetchall()
        return pd.DataFrame(data, columns=columns)
    aiosqlite.Cursor.execute_fetchall_pandas = _fetchall_pandas

logger = logging.getLogger(__name__)

class Visualizer:
    def __init__(self, db_path, output_dir="output"):
        self.db_path = db_path
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    async def _load_dataframe(self, table_name="hits"):
        logger.info(f"Loading data from database table '{table_name}'...")
        try:
            async with aiosqlite.connect(self.db_path) as db:
                async with db.execute(f"SELECT * FROM {table_name}") as cursor:
                    df = await cursor.execute_fetchall_pandas()
            if not df.empty: logger.info(f"Successfully loaded {len(df)} records.")
            return df
        except Exception as e:
            logger.error(f"Could not load data for visualization: {e}"); return pd.DataFrame()

    async def plot_top_heuristics(self, df):
        if 'heuristic' not in df.columns or df['heuristic'].isnull().all():
            logger.warning("Skipping 'Top Heuristics' plot: 'heuristic' column is missing or empty."); return
        logger.info("Generating 'Top Detection Heuristics' bar chart...")
        plt.style.use('seaborn-v0_8-whitegrid'); fig, ax = plt.subplots(figsize=(10, 8))
        top_items = df['heuristic'].value_counts().nlargest(10).sort_values(ascending=True)
        top_items.plot(kind='barh', ax=ax, color=sns.color_palette("rocket", len(top_items)))
        ax.set_title('Top 10 Detection Heuristics', fontsize=16, pad=20)
        ax.set_xlabel('Number of Listings', fontsize=12); ax.set_ylabel('Heuristic Type', fontsize=12)
        for index, value in enumerate(top_items): ax.text(value, index, f' {value}', va='center')
        plt.tight_layout(); output_path = os.path.join(self.output_dir, "top_heuristics.png")
        plt.savefig(output_path); logger.info(f"Chart saved to {output_path}"); plt.close(fig)

    async def plot_threat_composition(self, df):
        if 'dataset' not in df.columns:
            logger.warning("Skipping 'Threat Composition' plot: 'dataset' column is missing."); return
        logger.info("Generating 'Threat Composition' donut chart...")
        dataset_counts = df['dataset'].value_counts()
        plt.style.use('seaborn-v0_8-whitegrid'); fig, ax = plt.subplots(figsize=(8, 8))
        wedges, _, autotexts = ax.pie(dataset_counts, labels=dataset_counts.index, autopct='%1.1f%%', startangle=90, pctdistance=0.85, colors=sns.color_palette("Paired"))
        centre_circle = plt.Circle((0,0),0.70,fc='white'); fig.gca().add_artist(centre_circle)
        ax.axis('equal'); plt.title('Threat Composition by Dataset', fontsize=16, pad=20)
        plt.tight_layout(); output_path = os.path.join(self.output_dir, "threat_composition.png")
        plt.savefig(output_path); logger.info(f"Chart saved to {output_path}"); plt.close(fig)

    async def plot_threats_over_time(self, df):
        if 'listed' not in df.columns:
            logger.warning("Skipping 'Threats Over Time' plot: 'listed' column is missing."); return
        logger.info("Generating 'Threats Over Time' line chart...")
        df['listed_date'] = pd.to_datetime(df['listed'], unit='s')
        daily_counts = df.set_index('listed_date').resample('D').size()
        if len(daily_counts) < 2:
            logger.warning("Skipping 'Threats Over Time' plot: Not enough data for a trend line."); return
        plt.style.use('seaborn-v0_8-whitegrid'); fig, ax = plt.subplots(figsize=(12, 6))
        daily_counts.plot(kind='line', ax=ax, marker='o', linestyle='-')
        ax.set_title('Daily Threat Listings (Historical)', fontsize=16, pad=20)
        ax.set_xlabel('Date', fontsize=12); ax.set_ylabel('Number of Listings', fontsize=12)
        plt.xticks(rotation=45); plt.tight_layout()
        output_path = os.path.join(self.output_dir, "historical_threats_over_time.png")
        plt.savefig(output_path); logger.info(f"Chart saved to {output_path}"); plt.close(fig)

    async def generate_all_visuals(self):
        df = await self._load_dataframe(table_name="hits")
        if df.empty: logger.error("No live data loaded. Aborting visualization."); return
        logger.info("--- Starting Live Data Visualization Suite ---")
        await self.plot_top_heuristics(df)
        await self.plot_threat_composition(df)
        logger.info("--- Live Data Visualization Suite Finished ---")

    async def generate_history_visuals(self):
        df = await self._load_dataframe(table_name="history_hits")
        if df.empty: logger.error("No historical data loaded. Aborting visualization."); return
        logger.info("--- Starting Historical Data Visualization Suite ---")
        await self.plot_threats_over_time(df)
        logger.info("--- Historical Data Visualization Suite Finished ---")