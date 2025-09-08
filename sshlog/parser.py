import re
from datetime import datetime
from dateutil import tz
from dateutil.parser import parse as dtparse
import pandas as pd

# Syslog timestamps lack year; assume current year (good enough for demo)
_CURR_YEAR = datetime.now(tz=tz.tzlocal()).year

# Regexes for common OpenSSH lines
_RE_FAILED = re.compile(
      r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Failed password for (invalid user )?(?P<user>[\w\-]+) from (?P<ip>[\d\.:a-fA-F]+)"
)

_RE_ACCEPT = re.compile(
  r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Accepted password for (?P<user>[\w\-]+) from (?P<ip>[\d\.:a-fA-F]+)"
)

_RE_INVALID = re.compile(
  r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}).*sshd\[\d+\]: Invalid user (?P<user>[\w\-]+) from (?P<ip>[\d\.:a-fA-F]+)"
)

def _parse_ts(ts_text: str) -> datetime:
  # e.g., "Jan 10 12:34:56" -> add current year
  return dtparse(f"{ts_text} {_CURR_YEAR}")

def parse_logs(paths) -> pd.DataFrame:
  """
  Return a DataFrame with columns:
    ts (datetime), ip (str), user (str|None), event ('fail'|'invalid'|'success'), raw (str)
  """
  rows = []
  for p in paths:
    with open(p, "r", errors="ignore") as fh:
      for line in fh:
        line = line.rstrip('\n')
        m = _RE_FAILED.search(line)
        if m:
          rows.append(dict(
            ts=_parse_ts(m.group("ts")),
            ip=m.group('ip'),
            user=m.group('user'),
            event='fail',
            raw=line
          ))
          continue
        m = _RE_INVALID.search(line)
        if m:
          rows.append(dict(
            ts=_parse_ts(m.group('ts')),
            ip=m.group('ip'),
            user=m.group('user'),
            event="invalid",
            raw=line
          ))
          continue
        m = _RE_ACCEPT.search(line)
        if m:
          rows.append(dict(
            ts=_parse_ts(m.group("ts")),
            ip=m.group("ip"),
            user=m.group("user"),
            event="success",
            raw=line
          ))
          continue
  df = pd.DataFrame(rows)
  if not df.empty:
    df = df.sort_values('ts').reset_index(drop=True)
  return df
