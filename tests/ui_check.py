"""Log into Kibana as a user and check that key pages render without errors.

Run from the repo root (pulls the Playwright image the first time, ~2 GB):
    tests/ui-check.sh [user]      # default user: analyst
Screenshots land in tests/out/.
"""
import os
import sys
import time

from playwright.sync_api import sync_playwright

BASE = os.environ["KB"]
PAGES = {
    "dashboard": "/app/dashboards#/view/moat-home-network",
    "alerts": "/app/security/alerts",
    "rules": "/app/security/rules",
    "cases": "/app/security/cases",
    "discover": "/app/discover",
}
ERROR_SELECTORS = ('[data-test-subj="embeddableError"], [data-test-subj="embeddable-lens-failure"], '
                   '[data-test-subj="noPrivilegesPage"], .euiCallOut--danger')


def settle(pg, seconds=60):
    deadline = time.time() + seconds
    while time.time() < deadline:
        panels = pg.locator('[data-test-subj="dashboardPanel"]').count()
        done = pg.locator('[data-render-complete="true"]').count()
        if panels == 0 or done >= panels:
            break
        time.sleep(2)
    time.sleep(4)


def main():
    failed = 0
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(ignore_https_errors=True, viewport={"width": 1800, "height": 4400})
        pg.goto(f"{BASE}/login", wait_until="networkidle")
        pg.fill('[data-test-subj="loginUsername"]', os.environ["KU"])
        pg.fill('[data-test-subj="loginPassword"]', os.environ["KP"])
        pg.click('[data-test-subj="loginSubmit"]')
        pg.wait_for_url("**/app/**", timeout=60000)
        for name, path in PAGES.items():
            pg.goto(f"{BASE}{path}", wait_until="networkidle")
            settle(pg)
            errors = [e.replace("\n", " ")[:200] for e in pg.locator(ERROR_SELECTORS).all_inner_texts()]
            # Kibana's privilege warnings are *info* callouts, so match their text too.
            errors += [e.replace("\n", " ")[:200] for e in pg.locator(".euiCallOut").all_inner_texts()
                       if "privilege" in e.lower()]
            pg.screenshot(path=f"/out/{name}.png", full_page=True)
            status = "FAIL" if errors else "ok"
            failed += bool(errors)
            print(f"{status:4} {name:10} {path}")
            for e in errors:
                print(f"     ! {e}")
        b.close()
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
