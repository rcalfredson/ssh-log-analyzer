import pandas as pd
from datetime import datetime, timedelta
from sshlog.detect import detect_events


def _row(ts, ip, user, event):
    return dict(ts=ts, ip=ip, user=user, event=event, raw="")


def test_bruteforce_alert_triggers():
    t0 = datetime(2025, 1, 1, 12, 0, 0)
    rows = [
        _row(t0 + timedelta(seconds=0), "203.0.113.5", "root", "fail"),
        _row(t0 + timedelta(seconds=5), "203.0.113.5", "root", "fail"),
        _row(t0 + timedelta(seconds=10), "203.0.113.5", "root", "fail"),
    ]
    df = pd.DataFrame(rows)
    out = detect_events(df, threshold=3, window="1m")
    assert any(a["type"] == "brute_force" for a in out["alerts"])
