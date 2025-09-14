from collections import deque, defaultdict
from datetime import timedelta
import re
import pandas as pd


def _parse_window(s: str) -> timedelta:
    m = re.match(r"^(\d+)([smhd])$", s.strip())
    if not m:
        return timedelta(minutes=10)
    n, unit = int(m.group(1)), m.group(2)
    mult = dict(s=1, m=60, h=3600, d=86400)[unit]
    return timedelta(seconds=n * mult)


def _sliding_count(times, window: timedelta, threshold: int):
    """Yield (first, last, count) windows that meet threshold."""
    dq = deque()
    for t in times:
        dq.append(t)
        while dq and (t - dq[0]) > window:
            dq.popleft()
        if len(dq) >= threshold:
            yield dq[0], dq[-1], len(dq)


def detect_events(
    df: pd.DataFrame, threshold=5, window="10m", success_after_fails=5, geo=None
):
    if df is None or df.empty:
        return {
            "events": df,
            "meta": {"threshold": threshold, "window": window},
            "failed_by_ip": pd.DataFrame(),
            "alerts": [],
        }
    w = _parse_window(window)

    # Aggregate failures by IP
    fails = df[df["event"].isin(["fail", "invalid"])].copy()
    failed_by_ip = (
        fails.groupby("ip")
        .agg(fails=("event", "size"), first_seen=("ts", "min"), last_seen=("ts", "max"))
        .sort_values("fails", ascending=False)
        .reset_index()
    )
    alerts = []

    # Brute force per IP (fail + invalid combined)
    for ip, group in fails.groupby("ip"):
        times = list(group["ts"])
        for first, last, count in _sliding_count(times, w, threshold):
            alerts.append(
                {
                    "type": "brute_force",
                    "ip": ip,
                    "count": count,
                    "first_seen": first,
                    "last_seen": last,
                }
            )
            break  # mark once per IP for MVP

    # Invalid-user spray
    invalid = df[df["event"] == "invalid"]
    for ip, group in invalid.groupby("ip"):
        times = list(group["ts"])
        for first, last, count in _sliding_count(times, w, max(3, threshold - 1)):
            alerts.append(
                {
                    "type": "invalid_user_spray",
                    "ip": ip,
                    "count": count,
                    "first_seen": first,
                    "last_seen": last,
                }
            )
            break

    # Success after many fails (same IP or same user)
    successes = df[df["event"] == "success"]
    fail_by_ip = defaultdict(list)
    fail_by_user = defaultdict(list)
    for _, r in fails.iterrows():
        fail_by_ip[r.ip].append(r.ts)
        if isinstance(r.user, str):
            fail_by_user[r.user].append(r.ts)

    for _, srow in successes.iterrows():
        t = srow.ts
        ip = srow.ip
        user = srow.user
        recent_ip_fails = [x for x in fail_by_ip.get(ip, []) if t - x <= w]
        recent_user_fails = [x for x in fail_by_user.get(user, []) if t - x <= w]
        if (
            len(recent_ip_fails) >= success_after_fails
            or len(recent_user_fails) >= success_after_fails
        ):
            alerts.append(
                {
                    "type": "success_after_many_fails",
                    "ip": ip,
                    "user": user,
                    "count": max(len(recent_ip_fails), len(recent_user_fails)),
                    "first_seen": min(recent_ip_fails + recent_user_fails),
                    "last_seen": t,
                }
            )
    return {
        "events": df,
        "failed_by_ip": failed_by_ip,
        "alerts": alerts,
        "meta": {"threshold": threshold, "window": window},
    }
