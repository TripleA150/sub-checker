# sub-checker

Checks Xray-core subscriptions and keeps only working, encrypted keys.

Every 8 hours a GitHub Actions workflow (`.github/workflows/check.yml`):

1. reads `sources.txt`, which lists subscription URLs and/or individual keys, one per line;
2. keeps only `vless`/`vmess`/`trojan` keys whose security (`security=`, VMess `tls`) is
   explicitly `tls` or `reality`, or explicitly `none` **and** an encryption method other than
   `none` is set (VLESS `encryption=`, VMess `scy`). Keys without a security value, and
   Shadowsocks keys (which have none), are dropped, as are duplicates;
3. checks each server once: a TCP connect to its port (up to 3 tries), falling back to ICMP ping;
   keys whose server answers neither are dropped without starting Xray;
4. starts Xray-core for each remaining key and requests `https://www.gstatic.com/generate_204` through it,
   up to 3 times (one success counts as working);
5. commits the working keys to `valid.txt`.

If no key works at all (usually a network problem on the runner), `valid.txt` is left as it was
and the run fails.

## Run locally

Needs Python 3.8+, `curl`, `ping` (optional) and an [Xray-core](https://github.com/XTLS/Xray-core/releases) binary.

```sh
python3 checker.py sources.txt -o valid.txt --xray /path/to/xray
python3 checker.py -h   # --attempts, --timeout, --workers, --url
python3 -m unittest test_checker
```

To run it on your own server instead of GitHub Actions, add a cron entry:

```
0 */8 * * * cd /path/to/sub-checker && python3 checker.py sources.txt -o valid.txt --xray /usr/local/bin/xray
```

GitHub-hosted runners block outgoing ICMP, so there the pre-check relies on TCP.

Keys are tested from wherever the checker runs. A key that works from GitHub's servers
may still be blocked in your region, and the other way round.
