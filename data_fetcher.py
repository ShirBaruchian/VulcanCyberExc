import aiohttp
import csv
import os

class DataFetcher:
    BASE_URL = "http://interview.vulcancyber.com:3000"
    HEADERS = {"Authorization": "Aa123456!"}

    @staticmethod
    async def fetch_servers():
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{DataFetcher.BASE_URL}/servers", headers=DataFetcher.HEADERS) as response:
                response.raise_for_status()
                servers = await response.json()
                for server in servers:
                    yield server

    @staticmethod
    async def fetch_vulnerabilities(start_id, batch_size):
        async with aiohttp.ClientSession() as session:
            next_start = start_id
            while True:
                try:
                    async with session.post(
                            f"{DataFetcher.BASE_URL}/vulns",
                            json={"startId": next_start, "amount": batch_size},
                    ) as response:
                        if response.status == 400:
                            # End of data; log and break the loop
                            break
                        response.raise_for_status()
                        vulnerabilities = await response.json()

                        if not vulnerabilities:  # No vulnerabilities returned
                            break

                        for vuln in vulnerabilities:
                            yield vuln

                        next_start += batch_size

                except aiohttp.ClientResponseError as e:
                    break

    @staticmethod
    async def fetch_rules(file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Rules file not found at {file_path}")
        with open(file_path, mode="r") as file:
            reader = csv.DictReader(file)
            for row in reader:
                yield row
