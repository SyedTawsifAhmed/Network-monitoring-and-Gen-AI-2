import time
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

from poller import main as run_poller
from utils import load_yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
SETTINGS_PATH = "configs/settings.yaml"

load_dotenv(ENV_FILE)


def get_poll_interval():
    settings = load_yaml(SETTINGS_PATH)
    return settings["polling"].get("interval_seconds", 300)


def run_forever():
    print("[+] Scheduler started")

    while True:
        interval_seconds = get_poll_interval()
        cycle_start = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        print(f"\n[+] Starting poll cycle at {cycle_start}")
        print(f"[+] Poll interval: {interval_seconds} seconds")

        try:
            run_poller()
            print("[+] Poll cycle completed successfully")
        except Exception as e:
            print(f"[!] Poll cycle failed: {e}")

        print(f"[+] Sleeping for {interval_seconds} seconds...")
        time.sleep(interval_seconds)


if __name__ == "__main__":
    run_forever()