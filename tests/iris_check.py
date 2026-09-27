"""Log into DFIR-IRIS through Caddy and check the alerts page renders.
Run via tests/ui-check.sh iris. Screenshots land in tests/out/."""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = os.environ["KB"]
with sync_playwright() as p:
    b = p.chromium.launch()
    pg = b.new_page(ignore_https_errors=True, viewport={"width": 1600, "height": 1100})
    pg.goto(f"{BASE}/login", wait_until="networkidle")
    pg.fill('input[name="username"]', os.environ["KU"])
    pg.fill('input[name="password"]', os.environ["KP"])
    pg.click('button[type="submit"]')
    pg.wait_for_load_state("networkidle")
    ok = "/login" not in pg.url
    print(f"{'ok' if ok else 'FAIL':4} login      -> {pg.url}")
    pg.goto(f"{BASE}/alerts", wait_until="networkidle")
    pg.wait_for_timeout(4000)
    pg.screenshot(path="/out/iris-alerts.png", full_page=False)
    rows = pg.locator("[id^='alertCard-'], .alert-card, #alertsList .card").count()
    print(f"{'ok' if rows else 'FAIL':4} alerts     {rows} alert cards visible")
    b.close()
    sys.exit(0 if ok and rows else 1)
