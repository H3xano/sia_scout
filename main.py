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


def setup_logging():
    """Configures the root logger for the application."""
    log_format = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(config.LOG_FILE)
    file_handler.setFormatter(log_format)
    root_logger.addHandler(file_handler)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_format)
    root_logger.addHandler(console_handler)


async def main_async():
    """Asynchronous main function to run the SIA-Scout scanner."""
    setup_logging()
    logger = logging.getLogger(__name__)

    parser = argparse.ArgumentParser(description="SIA-Scout: A Spamhaus Intelligence API scanner.")
    parser.add_argument(
        'action',
        choices=['collect', 'analyze'],
        help="The action to perform: 'collect' data from the API, or 'analyze' existing data."
    )
    args = parser.parse_args()

    if not config.SIA_USERNAME or not config.SIA_PASSWORD:
        logger.critical("Please set SIA_USERNAME and SIA_PASSWORD in the .env file.")
        return

    logger.info(f"--- SIA-Scout Initializing | Action: {args.action.upper()} ---")

    await initialize_database(config.DATABASE_FILE)

    if args.action == 'collect':
        client = AsyncSiaClient(
            base_url=config.API_BASE_URL,
            username=config.SIA_USERNAME,
            password=config.SIA_PASSWORD,
            token_file=config.TOKEN_FILE
        )

        # FIX: Check limits using the sync method before starting the async collection
        client.check_limits_sync()

        query_params = {
            'dataset': config.SIA_DATASET,
            'mode': config.SIA_MODE,
            'type': config.SIA_TYPE,
            'limit': config.SIA_LIMIT,
        }
        collector = AsyncCollector(
            client=client,
            target_file=config.TARGET_FILE,
            db_path=config.DATABASE_FILE,
            concurrency=config.CONCURRENCY_LIMIT,
            params=query_params
        )
        await collector.run_scan()

    elif args.action == 'analyze':
        analyzer = Analyzer(db_path=config.DATABASE_FILE)
        await analyzer.generate_summary_report()


if __name__ == "__main__":
    try:
        asyncio.run(main_async())
    except KeyboardInterrupt:
        print("\nOperation interrupted by user.")