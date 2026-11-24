#!/usr/bin/env python3
"""Deterministic synthetic data for the examples (no real people)."""
import csv, hashlib, random, sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

root = Path(__file__).resolve().parent.parent / "examples"
rnd = random.Random(20261121)

# --- personal vault: Alice's calendar (two weeks from 2026-11-23 plus noise)
events = []
start = datetime(2026, 11, 23, tzinfo=timezone.utc)
titles = ["1:1 with Bob", "Dentist", "Board prep", "Gym", "Flight to Lisbon", "School pickup", "Design review", "Lunch w/ Carol"]
for d in range(28):
    day = start + timedelta(days=d)
    if day.weekday() >= 5:
        continue
    for _ in range(rnd.randint(1, 4)):
        h = rnd.randint(8, 17)
        m = rnd.choice([0, 15, 30, 45])
        s = day.replace(hour=h, minute=m)
        e = s + timedelta(minutes=rnd.choice([30, 45, 60, 90, 120]))
        events.append({
            "event_id": f"ev{len(events):04d}",
            "start_at": s.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "end_at": e.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "status": rnd.choice(["confirmed"] * 9 + ["cancelled"]),
            "title": rnd.choice(titles),
            "attendees": ";".join(rnd.sample(["bob@example.com", "carol@example.com", "dan@example.com", "erin@example.com"], 2)),
            "location": rnd.choice(["Office", "Home", "Zoom", "Clinic"]),
        })
events.sort(key=lambda r: r["start_at"])
p = root / "personal-vault" / "data" / "events.csv"
with p.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(events[0].keys()))
    w.writeheader()
    w.writerows(events)

# Health metrics in SQLite (to exercise the sqlite connector).
db = root / "personal-vault" / "data" / "health.sqlite"
db.unlink(missing_ok=True)
con = sqlite3.connect(db)
con.execute("CREATE TABLE steps (day TEXT, steps INTEGER, resting_hr INTEGER)")
for d in range(60):
    day = (datetime(2026, 9, 23) + timedelta(days=d)).strftime("%Y-%m-%d")
    con.execute("INSERT INTO steps VALUES (?, ?, ?)", (day, rnd.randint(2000, 16000), rnd.randint(52, 70)))
con.commit()
con.close()

# --- enterprise analytics: CRM accounts + deals
regions = ["EMEA", "AMER", "APAC", "LATAM"]
segments = ["smb", "mid", "enterprise"]
accounts = []
for i in range(2400):
    region = rnd.choices(regions, weights=[35, 40, 20, 5])[0]
    seg = rnd.choices(segments, weights=[60, 30, 10])[0]
    base = {"smb": 8_000, "mid": 60_000, "enterprise": 400_000}[seg]
    accounts.append({
        "account_id": f"acc{i:05d}",
        "name": f"Company {i}",
        "region": region,
        "segment": seg,
        "arr": round(rnd.lognormvariate(0, 0.6) * base, 2),
        "owner_email": f"rep{rnd.randint(1, 40)}@vendor.example",
        "created_at": (datetime(2023, 1, 1) + timedelta(days=rnd.randint(0, 1400))).strftime("%Y-%m-%dT00:00:00Z"),
    })
p = root / "enterprise-analytics" / "data" / "accounts.csv"
with p.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(accounts[0].keys()))
    w.writeheader()
    w.writerows(accounts)
deals = []
for i in range(6000):
    a = rnd.choice(accounts)
    deals.append({
        "deal_id": f"deal{i:05d}",
        "account_id": a["account_id"],
        "stage": rnd.choices(["open", "won", "lost"], weights=[30, 45, 25])[0],
        "amount": round(rnd.lognormvariate(0, 0.8) * 20_000, 2),
        "closed_at": (datetime(2025, 1, 1) + timedelta(days=rnd.randint(0, 690))).strftime("%Y-%m-%dT00:00:00Z"),
    })
p = root / "enterprise-analytics" / "data" / "deals.csv"
with p.open("w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(deals[0].keys()))
    w.writeheader()
    w.writerows(deals)

# --- b2b overlap: Company B's customers (email hashes); Company A's list is in the demo.
emails = [f"user{i}@shop.example" for i in range(5000)]
cust = rnd.sample(emails, 1800)
p = root / "b2b-overlap" / "data" / "customers.csv"
with p.open("w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["customer_id", "email", "email_sha256", "country", "lifetime_value"])
    for i, e in enumerate(cust):
        w.writerow([f"c{i:05d}", e, hashlib.sha256(e.encode()).hexdigest(), rnd.choice(["DE", "FR", "US", "PT", "JP"]), round(rnd.uniform(5, 900), 2)])
mine = rnd.sample(emails, 400)
(root / "b2b-overlap" / "data" / "company-a-list.txt").write_text("\n".join(mine) + "\n")
print("example data written")
