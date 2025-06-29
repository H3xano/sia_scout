# FILE: sia_scout/client.py

import logging
import asyncio
import aiohttp
import sys
import requests
import os
import json
import time

logger = logging.getLogger(__name__)

class AsyncSiaClient:
    """An ASYNC client for the Spamhaus Intelligence API."""

    def __init__(self, base_url, username, password, token_file):
        self.base_url = base_url
        self.username = username
        self.password = password
        self.token_file = token_file
        self.token = None
        self.token_expires = 0
        self.session = None

    def initial_auth(self):
        if os.path.exists(self.token_file):
            with open(self.token_file, 'r') as f:
                try:
                    data = json.load(f)
                    if time.time() < (data.get('expires', 0) - 60):
                        self.token = data.get('token')
                        logger.info("Loaded valid token from file.")
                        return
                except json.JSONDecodeError: pass
        logger.info("Requesting a new authentication token...")
        login_url = f"{self.base_url}/api/v1/login"
        creds = {"username": self.username, "password": self.password, "realm": "intel"}
        try:
            response = requests.post(login_url, json=creds)
            if response.status_code == 200:
                data = response.json()
                self.token = data.get('token')
                self.token_expires = data.get('expires', 0)
                with open(self.token_file, 'w') as f: json.dump({'token': self.token, 'expires': self.token_expires}, f)
                logger.info("Authentication successful, token saved.")
            else:
                logger.critical(f"Authentication failed: {response.text}"); sys.exit(1)
        except requests.exceptions.RequestException as e:
            logger.critical(f"Network error during auth: {e}"); sys.exit(1)

    def check_limits_sync(self):
        if not self.token: self.initial_auth()
        headers = {"Authorization": f"Bearer {self.token}"}
        url = f"{self.base_url}/api/intel/v1/limits"
        print("\n--- Checking Account Status ---")
        try:
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                logger.warning(f"Could not retrieve limits: Status {response.status_code}"); return
            limits_data = response.json()
            account = limits_data.get('account', {})
            limits = limits_data.get('limits', {})
            current = limits_data.get('current', {})
            report = "ACCOUNT:\n"
            report += f"  - User: {account.get('usr', 'N/A')}\n  - Subscription ID: {account.get('sub', 'N/A')}\n\n"
            report += "GLOBAL LIMITS:\n"
            report += f"  - Allowed Datasets: {limits.get('ads', 'N/A')}\n  - Access Level: {limits.get('trs', 'N/A')}\n"
            report += f"  - Queries/Month (Soft Limit): {limits.get('qms', 'N/A')}\n  - Queries/Month (Hard Limit): {limits.get('qmh', 'N/A')}\n\n"
            report += "RATE LIMITS (Per Time Period):\n"
            report += f"  - Per Second: {limits.get('rl_qps', 'N/A')}\n  - Per Minute: {limits.get('rl_qpm', 'N/A')}\n  - Per Hour:   {limits.get('rl_qph', 'N/A')}\n\n"
            report += "CURRENT USAGE:\n"
            report += f"  - This Month: {current.get('qpm', 'N/A')}\n  - Today:      {current.get('qpd', 'N/A')}\n"
            print(report); print("---------------------------------\n")
        except requests.exceptions.RequestException as e:
            logger.error(f"Network error checking limits: {e}")

    async def create_session(self):
        if self.token is None: self.initial_auth()
        headers = {"Authorization": f"Bearer {self.token}"}
        self.session = aiohttp.ClientSession(headers=headers)

    async def close_session(self):
        if self.session: await self.session.close()

    async def get_cidr_listings(self, cidr_str, dataset, mode, limit, since=None, until=None):
        """(ASYNC) Gets listings within a CIDR. Supports both LIVE and HISTORY modes."""
        if since and until:
            query_type = "history"
            params = {"limit": limit, "since": since, "until": until}
        else:
            query_type = "live"
            params = {"limit": limit}
        url = f"{self.base_url}/api/intel/v1/byobject/cidr/{dataset}/{mode}/{query_type}/{cidr_str}"
        try:
            async with self.session.get(url, params=params) as response:
                if response.status == 200: return await response.json()
                if response.status == 404: return {"code": 404, "results": []}
                if response.status == 429: logger.critical("429 - TOO MANY REQUESTS. API limit hit."); sys.exit(1)
                logger.warning(f"API returned status {response.status} for CIDR {cidr_str}"); return None
        except aiohttp.ClientError as e:
            logger.error(f"Network client error querying {cidr_str}: {e}"); return None