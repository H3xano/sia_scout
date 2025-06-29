# FILE: sia_scout/collector.py

import logging
import asyncio
import ipaddress
import time
import aiosqlite
from . import database

logger = logging.getLogger(__name__)

# A constant list of all DB columns to ensure consistency.
DB_COLUMNS = [
    'dataset', 'ipaddress', 'asn', 'cc', 'listed', 'seen', 'valid_until', 'rule',
    'botname', 'botname_malpedia', 'dstport', 'heuristic', 'lat', 'lon',
    'protocol', 'srcip', 'domain', 'helo', 'detection'
]


class AsyncCollector:
    def __init__(self, client, target_file, db_path, concurrency, params):
        self.client = client
        self.target_file = target_file
        self.db_path = db_path
        self.semaphore = asyncio.Semaphore(concurrency)
        self.db_lock = asyncio.Lock()
        self.params = params
        self.queue = asyncio.Queue()

    # --- Live Scan Methods ---
    async def _live_producer(self):
        logger.info("Producer started: Reading and splitting target CIDRs for LIVE scan.")
        async with aiosqlite.connect(self.db_path) as db:
            with open(self.target_file, 'r') as f:
                for line in f:
                    cidr_str = line.strip()
                    if not cidr_str or cidr_str.startswith('#'): continue
                    try:
                        network = ipaddress.ip_network(cidr_str)
                        subnets = list(network.subnets(new_prefix=24)) if network.prefixlen < 24 else [network]
                        for subnet in subnets:
                            subnet_str = str(subnet)
                            async with self.db_lock:
                                if not await database.check_if_scanned(db, subnet_str):
                                    await self.queue.put(subnet_str)
                                else:
                                    logger.debug(f"[CACHE HIT] {subnet_str} already scanned. Skipping.")
                    except ValueError:
                        logger.error(f"Invalid CIDR format: {cidr_str}")
        for _ in range(self.semaphore._value): await self.queue.put(None)

    async def _live_worker(self, name):
        async with aiosqlite.connect(self.db_path) as db:
            while True:
                subnet_str = await self.queue.get()
                if subnet_str is None: self.queue.put_nowait(None); break
                async with self.semaphore:
                    logger.info(f"[{name}] Querying LIVE for {subnet_str}...")
                    response = await self.client.get_cidr_listings(cidr_str=subnet_str, **self.params)

                    if response and response.get('results'):
                        hits = response.get('results', [])
                        if len(hits) >= self.params['limit']:
                            logger.warning(
                                f"CIDR {subnet_str} hit the LIVE query limit of {self.params['limit']}. Some data may be missing.")

                        # FIX: Ensure all required DB columns exist in each hit dictionary
                        for hit in hits:
                            for key in DB_COLUMNS: hit.setdefault(key, None)

                        async with self.db_lock:
                            count = await database.insert_hits(db, hits)
                            logger.info(f"[{name}]   -> Found and saved {count} LIVE listings for {subnet_str}.")

                    async with self.db_lock:
                        await database.mark_as_scanned(db, subnet_str, int(time.time()))
                self.queue.task_done()
        logger.info(f"[{name}] live worker finished.")

    # --- History Scan Methods ---
    async def _history_producer(self):
        logger.info("Producer started: Reading and splitting target CIDRs for HISTORY scan.")
        with open(self.target_file, 'r') as f:
            for line in f:
                cidr_str = line.strip()
                if not cidr_str or cidr_str.startswith('#'): continue
                try:
                    network = ipaddress.ip_network(cidr_str)
                    subnets = list(network.subnets(new_prefix=24)) if network.prefixlen < 24 else [network]
                    for subnet in subnets: await self.queue.put(str(subnet))
                except ValueError:
                    logger.error(f"Invalid CIDR format: {cidr_str}")
        for _ in range(self.semaphore._value): await self.queue.put(None)

    async def _history_worker(self, name, since_ts, until_ts):
        async with aiosqlite.connect(self.db_path) as db:
            while True:
                subnet_str = await self.queue.get()
                if subnet_str is None: self.queue.put_nowait(None); break
                async with self.semaphore:
                    logger.info(f"[{name}] Querying HISTORY for {subnet_str}...")
                    response = await self.client.get_cidr_listings(cidr_str=subnet_str, since=since_ts, until=until_ts,
                                                                   **self.params)

                    if response and response.get('results'):
                        hits = response.get('results', [])
                        if len(hits) >= self.params['limit']:
                            logger.warning(
                                f"CIDR {subnet_str} hit the HISTORY query limit of {self.params['limit']}. Some historical data may be missing.")

                        # FIX: Ensure all required DB columns exist in each hit dictionary
                        for hit in hits:
                            for key in DB_COLUMNS: hit.setdefault(key, None)

                        async with self.db_lock:
                            count = await database.insert_history_hits(db, hits)
                            logger.info(f"[{name}]   -> Found and saved {count} HISTORICAL listings for {subnet_str}.")
                self.queue.task_done()
        logger.info(f"[{name}] history worker finished.")

    # --- Main Orchestrator ---
    async def run_scan(self, history_days=None):
        await self.client.create_session()
        try:
            start_time = time.time()
            if history_days:
                logger.info(f"--- Starting History Scan (Last {history_days} Days) ---")
                until_ts = int(time.time())
                since_ts = until_ts - (history_days * 86400)
                producer = self._history_producer()
                workers = [self._history_worker(f"Worker-{i + 1}", since_ts, until_ts) for i in
                           range(self.semaphore._value)]
            else:
                logger.info("--- Starting Live Scan ---")
                producer = self._live_producer()
                workers = [self._live_worker(f"Worker-{i + 1}") for i in range(self.semaphore._value)]

            await asyncio.gather(asyncio.create_task(producer), *[asyncio.create_task(w) for w in workers])
            logger.info(f"✅ Scan finished in {time.time() - start_time:.2f} seconds.")
        finally:
            logger.info("Closing network session...")
            await self.client.close_session()