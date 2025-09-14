from sshlog.parser import parse_logs


def test_parses_three_times(tmp_path):
    p = tmp_path / "auth.log"
    p.write_text(
        "Jan 10 12:00:00 host sshd[1]: Failed password for root from 203.0.113.5 port 1 ssh2\n"
        "Jan 10 12:00:05 host sshd[1]: Invalid user admin from 203.0.113.5 port 2 ssh2\n"
        "Jan 10 12:00:10 host sshd[1]: Accepted password for bob from 198.51.100.9 port 3 ssh2\n"
    )
    df = parse_logs([str(p)])
    assert len(df) == 3
    assert set(df.event.unique()) == {"fail", "invalid", "success"}
