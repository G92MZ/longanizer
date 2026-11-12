# Data model

Every log line or block becomes one row of the `events` table (DuckDB, timestamps in **UTC**):
common columns that every format fills when it can, source-specific fields in the `extra` JSON, and
the original text in `raw`.

| Column | | Filled by |
|---|---|---|
| `ts` | timestamp, UTC | every format with a time (not `dmesg`) |
| `source` | the log type — see [Log formats](../log-formats.md) | all |
| `host` · `program` · `pid` | | syslog-style logs |
| `severity` | | logfmt, applog, web error logs |
| `user` | | auth, sudo, auditd, bash_history, CSV… |
| `src_ip` · `src_port` | client / remote address | auth, access, weberror, auditd `saddr`, firewall |
| `exe` | the executable | auditd, sudo, bash_history |
| `method` · `path` · `status` · `bytes` · `referer` · `user_agent` | HTTP request | access |
| `event` | normalized event type | `ssh_accepted`, `ssh_failed`, `ssh_invalid_user`, `sudo`, `session_opened` / `closed`, `http_request`, `execve`, `syscall`, `user_auth`, `web_error`, `command`, `kernel`, `dpkg`, `uevent` |
| `message` | the readable message | all |
| `extra` | source-specific fields | JSON: auditd `syscall`, `key`, `serial`, `auid`, `cwd`…, logfmt and CSV keys |
| `src_file` · `line_no` | where the event came from | all |
| `raw` | the original line or block | all |

Every field is reachable: by name in the search box (`comm:wget`), as a column from the
**Columns** panel, or in SQL with `extra->>'key'`. `/schema` returns the columns as JSON.
