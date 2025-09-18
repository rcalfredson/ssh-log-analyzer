import argparse
from .parser import parse_logs
from .detect import detect_events
from .report import print_cli, write_csv, write_html


def main():
    p = argparse.ArgumentParser(description="SSH Log Analyzer")
    p.add_argument(
        "--log",
        action="append",
        required=True,
        help="Path to an auth log (repeatable).",
    )
    p.add_argument(
        "--threshold", type=int, default=5, help="Fails per IP to flag brute-force."
    )
    p.add_argument("--window", default="10m", help="Time window like 10m, 1h, 1d.")
    p.add_argument(
        "--csv", help="Base CSV path (creates *_failed.csv and *_alerts.csv)."
    )
    p.add_argument("--html", help="Write HTML report to this path.")
    args = p.parse_args()

    df = parse_logs(args.log)
    findings = detect_events(df, threshold=args.threshold, window=args.window)

    if not args.csv and not args.html:
        print_cli(findings)
    if args.csv:
        write_csv(findings, args.csv)
    if args.html:
        write_html(findings, args.html)


if __name__ == "__main__":
    main()
