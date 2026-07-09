import asyncio
import json
import time
from pathlib import Path
import aiohttp
import schedule
import threading

BASE_URL = "https://horizons.hackclub.com/api/projects"
OUTPUT_FILE = Path("data/projects.json")
MAX_ID = 9999
CONCURRENT = 50  # requests at a time

async def fetch_project(session, sem, pid, results):
    async with sem:
        try:
            async with session.get(f"{BASE_URL}/{pid}", timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    if data and data.get("projectId"):
                        results.append(data)
                        print(f"  Found: ID={data['projectId']}  {data.get('projectTitle','?')}  by {data.get('user',{}).get('displayName','?')}")
                elif resp.status != 404:
                    print(f"  [{pid}] HTTP {resp.status}")
        except Exception as e:
            pass  # skip timeouts / errors silently

async def main():
    print(f"Scanning IDs 1-{MAX_ID} ({CONCURRENT} concurrent)...")
    start = time.time()
    results = []
    sem = asyncio.Semaphore(CONCURRENT)

    connector = aiohttp.TCPConnector(limit=CONCURRENT, limit_per_host=CONCURRENT)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_project(session, sem, pid, results) for pid in range(1, MAX_ID + 1)]
        # run in chunks to show progress
        chunk_size = 500
        for i in range(0, len(tasks), chunk_size):
            chunk = tasks[i:i + chunk_size]
            await asyncio.gather(*chunk)
            elapsed = time.time() - start
            pct = min(100, (i + chunk_size) / MAX_ID * 100)
            print(f"  Progress: {pct:.0f}%  ({i + chunk_size}/{MAX_ID})  found={len(results)}  elapsed={elapsed:.0f}s")

    elapsed = time.time() - start
    print(f"\nDone! Scanned {MAX_ID} IDs in {elapsed:.0f}s. Found {len(results)} projects.")

    # sort by projectId
    results.sort(key=lambda p: p["projectId"])

    OUTPUT_FILE.write_text(json.dumps(results, indent=2), "utf-8")
    print(f"Saved to {OUTPUT_FILE}")

def async_main_wrapper():
    asyncio.run(main())

def scheduler_loop():
    print("scheduler start")

    # we use wrapper since scheduler doesn't handle async functions itself
    schedule.every().day.at("23:59").do(async_main_wrapper)

    while True:
        schedule.run_pending()

        # optimization :3        
        idle_seconds = schedule.idle_seconds()
        print("sleeping for ", idle_seconds)
        time.sleep(idle_seconds or 60)

if __name__ == "__main__":
    asyncio.run(main())
