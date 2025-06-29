# FILE: sia_scout/collector.py

import logging
import asyncio
import ipaddress
import time
import aiosqlite
from . import database

logger = logging.getLogger(__name__)


class AsyncCollector:
    def __init__(self, client, target_file, db_path, concurrency, params):
        self.client = client
        self.target_file = target_file
        self.db_path = db_path
        self.semaphore = asyncio.Semaphore(concurrency)
        # --- NEW: Create a lock specifically for database write operations ---
        self.db_lock = asyncio.Lock()
        self.params = params
        self.queue = asyncio.Queue()

    async def _producer(self):
        """Reads CIDRs, splits them, and puts valid subnets onto the queue."""
        logger.info("Producer started: Reading and splitting target CIDRs.")
        # Open a short-lived connection just for the producer's cache check
        async with aiosqlite.connect(self.db_path) as db:
            with open(self.target_file, 'r') as f:
                for line in f:
                    cidr_str = line.strip()
                    if not cidr_str or cidr_str.startswith('#'):
                        continue

                    try:
                        network = ipaddress.ip_network(cidr_str)
                        subnets_to_process = list(network.subnets(new_prefix=24)) if network.prefixlen < 24 else [
                            network]

                        for subnet in subnets_to_process:
                            subnet_str = str(subnet)
                            # We still need to acquire the lock for this read to be safe
                            async with self.db_lock:
                                if not await database.check_if_scanned(db, subnet_str):
                                    await self.queue.put(subnet_str)
                                else:
                                    logger.debug(f"[CACHE HIT] {subnet_str} already scanned. Skipping.")
                    except ValueError:
                        logger.error(f"Invalid CIDR format in target file: {cidr_str}")

        logger.info(f"Producer finished. Found {self.queue.qsize()} subnets to scan.")
        for _ in range(self.semaphore._value):
            await self.queue.put(None)

    async def _worker(self, name):
        """Pulls a subnet from the queue, queries it, and saves the results."""
        # Each worker gets its own long-lived connection
        async with aiosqlite.connect(self.db_path) as db:
            while True:
                subnet_str = await self.queue.get()
                if subnet_str is None:
                    self.queue.put_nowait(None)
                    break

                async with self.semaphore:
                    logger.info(f"[{name}] Querying {subnet_str}...")
                    response = await self.client.get_cidr_listings(
                        cidr_str=subnet_str,
                        dataset=self.params['dataset'],
                        mode=self.params['mode'],
                        type=self.params['type'],
                        limit=self.params['limit']
                    )

                    # --- NEW: Acquire the database lock before any database writes ---
                    async with self.db_lock:
                        # Mark as scanned first, even if there are no hits.
                        await database.mark_as_scanned(db, subnet_str, int(time.time()))

                        if response and response.get('results'):
                            hits = response.get('results', [])
                            for hit in hits:
                                for key in ['botname', 'botname_malpedia', 'dstport', 'heuristic', 'lat', 'lon',
                                            'protocol', 'srcip', 'domain', 'helo']:
                                    hit.setdefault(key, None)

                            count = await database.insert_hits(db, hits)
                            logger.info(f"[{name}]   -> Found and saved {count} listings for {subnet_str}.")

                self.queue.task_done()
        logger.info(f"[{name}] worker finished.")

    async def run_scan(self):
        """Orchestrates the entire asynchronous scan process."""
        await self.client.create_session()

        try:
            start_time = time.time()
            logger.info("--- Starting Asynchronous Scan ---")

            producer_task = asyncio.create_task(self._producer())
            worker_tasks = [asyncio.create_task(self._worker(f"Worker-{i + 1}")) for i in range(self.semaphore._value)]

            await asyncio.gather(producer_task, *worker_tasks)

            end_time = time.time()
            logger.info(f"✅ Scan finished in {end_time - start_time:.2f} seconds.")

        finally:
            # --- NEW: This ensures the session is always closed, even on error ---
            logger.info("Closing network session...")
            await self.client.close_session()