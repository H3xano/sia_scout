# FILE: main.py

import logging
import sys
import asyncio
import argparse
import config
from sia_scout.client import AsyncSiaClient
from sia_scout.collector import AsyncCollector
from sia_scout.database import initialize_database
from sia_scout.analyzer import Analyzer
from sia_scout.visualizer import Visualizer


def setup_logging():
    log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(config.LOG_FILE)
    file_handler.setFormatter(log_format)
    root_logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    root_logger.addHandler(console_handler)


async def main_async():
    setup_logging()
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="SIA-Scout: A Spamhaus Intelligence API scanner.")
    subparsers = parser.add_subparsers(dest='action', required=True, help='Available actions')

    p_collect = subparsers.add_parser('collect', help="Scan for LIVE listings using the cache.")
    p_collect_hist = subparsers.add_parser('collect-history', help="Scan for HISTORICAL listings (no cache).")
    p_collect_hist.add_argument('--days', type=int, default=config.HISTORY_LOOKBACK_DAYS,
                                help=f"Number of days to look back. Default: {config.HISTORY_LOOKBACK_DAYS}")
    p_analyze = subparsers.add_parser('analyze', help="Analyze LIVE data from the database.")
    p_analyze_hist = subparsers.add_parser('analyze-history', help="Analyze HISTORICAL data from the database.")
    p_visualize = subparsers.add_parser('visualize', help="Visualize LIVE data.")
    p_visualize_hist = subparsers.add_parser('visualize-history', help="Visualize HISTORICAL data.")

    args = parser.parse_args()

    if not config.SIA_USERNAME or not config.SIA_PASSWORD:
        logger.critical("Please set SIA_USERNAME and SIA_PASSWORD in the .env file.");
        return

    logger.info(f"--- SIA-Scout Initializing | Action: {args.action.upper()} ---")
    await initialize_database(config.DATABASE_FILE)

    if args.action == 'collect' or args.action == 'collect-history':
        client = AsyncSiaClient(base_url=config.API_BASE_URL, username=config.SIA_USERNAME,
                                password=config.SIA_PASSWORD, token_file=config.TOKEN_FILE)
        client.check_limits_sync()
        query_params = {'dataset': config.SIA_DATASET, 'mode': config.SIA_MODE, 'limit': config.SIA_LIMIT}
        collector = AsyncCollector(client=client, target_file=config.TARGET_FILE, db_path=config.DATABASE_FILE,
                                   concurrency=config.CONCURRENCY_LIMIT, params=query_params)
        history_days = args.days if args.action == 'collect-history' else None
        await collector.run_scan(history_days=history_days)

    elif args.action == 'analyze':
        analyzer = Analyzer(db_path=config.DATABASE_FILE)
        await analyzer.generate_summary_report()

    elif args.action == 'analyze-history':
        analyzer = Analyzer(db_path=config.DATABASE_FILE)
        await analyzer.generate_history_summary_report()

    elif args.action == 'visualize':
        visualizer = Visualizer(db_path=config.DATABASE_FILE)
        await visualizer.generate_all_visuals()

    elif args.action == 'visualize-history':
        visualizer = Visualizer(db_path=config.DATABASE_FILE)
        await visualizer.generate_history_visuals()


if __name__ == "__main__":
    try:
        asyncio.run(main_async());
    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")