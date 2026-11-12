# Log formats

Longanizer detects each file's type in two steps: by **name** first (`auth.log`, `secure`,
`messages`, `access.log`…, also rotated and compressed: `auth.log.1`, `messages.2.gz`), then by
**content** when the name gives no hint (a renamed or unnamed dump). You can force a type from the
CLI with `--type`.

Every line or block becomes one event in the `events` table, with its `source` set to the type
below. Nothing is dropped: input that can't be parsed still lands in `raw`.

| `source` | What | Notes |
|---|---|---|
| `auth` | `auth.log`, `secure` | sshd (accepted / failed / invalid user), sudo `COMMAND=`, su, logins, sessions |
| `syslog` | `syslog`, `messages` | RFC 3164 and ISO timestamps |
| `kern` | `kern.log` | kernel messages, including netfilter / iptables drops (`SRC=`, `DST=`, `DPT=`) |
| `cron` | `cron` | |
| `access` | web access logs | Apache / Nginx combined: method, path, status, bytes, referer, user agent |
| `weberror` | web `error.log` | Apache and Nginx error logs |
| `auditd` | `audit.log` | records stitched by `serial`; see below |
| `bash_history` | `.bash_history`, `*.history` | one command per event; the owner with `--user` |
| `logfmt` · `applog` | application logs | `key=value` logs: the keys go to `extra` |
| `csv` | `*.csv` | the header names the fields; known columns (`user`, `ip`, `status`, `time`…) map to real columns, the rest go to `extra`; quoted commas handled |
| `dmesg` | kernel ring buffer | `[ 0.000000] message` — seconds since boot, so **no timeline time** (kept in `extra.ktime`), still searchable |
| `apt` | apt / dpkg `term.log` | each `Log started:` … `Log ended:` block is one event, package actions summarised |
| `fontconfig` | fontconfig / fc-cache | one line per event |
| `udev` | `udevadm monitor` | each `UEVENT[epoch]` / `UDEV [epoch]` block is one event, `KEY=value` lines in `extra` |

!!! tip "One format per file"
    Best results come from loading each format as its own file. A file that mixes several formats
    is still ingested in full, but it is detected as a single type.

Binary logs (`wtmp`, `btmp`, `lastlog`) are not supported and are rejected; archives
(`.zip`, `.tar.gz`, `.gz`…) are extracted and walked.

## auditd

auditd records that belong together (same `serial`) are stitched into one event:

- **EXECVE** becomes the full command line, enriched with `exe`, `ppid`, `cwd` and the parent
  executable;
- hex-encoded arguments and `proctitle` are decoded, and **`saddr`** (socket addresses) becomes an
  IP and port;
- decoded values are shown *in italics* in the tables;
- `syscall`, `key`, `serial`, `auid`, `comm`… stay in `extra`, reachable by name in the search
  (`comm:wget`, `key:exec_watch`).

## Time zones

Everything is stored in **UTC**. Some logs don't carry their time zone — syslog, auth, kern, cron,
applog and the web `error.log` — so give the **time offset** in minutes when you load them
(the field in the Load tab, `--tz` in the CLI, `tz_offset_minutes` in the API):

| Offset | Zone |
|---|---|
| `+120` | CEST (Spain, summer) |
| `+60` | CET |
| `0` | UTC (default) |
| `-300` | EST |

Web access logs and auditd already carry UTC (or an explicit offset) and are left untouched.
For syslog lines without a year, `--year` sets the base year.
