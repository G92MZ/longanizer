# SQL recipes

Paste them into the [SQL](../investigate/sql.md) tab.

```sql
-- SSH brute force by source IP
SELECT src_ip, count(*) AS n FROM events
WHERE source = 'auth' AND message ILIKE '%failed password%'
GROUP BY src_ip ORDER BY n DESC;
```

```sql
-- commands run through sudo (COMMAND=)
SELECT ts, "user", message FROM events
WHERE source = 'auth' AND message LIKE '%COMMAND=%'
ORDER BY ts;
```

```sql
-- auditd execve of a given binary
SELECT ts, exe, message FROM events
WHERE source = 'auditd' AND event = 'execve' AND exe LIKE '%/wget'
ORDER BY ts;
```

```sql
-- a value from the extra JSON (auditd)
SELECT ts, exe, (extra->>'key') AS rule FROM events
WHERE source = 'auditd' AND (extra->>'key') IS NOT NULL
ORDER BY ts;
```

```sql
-- web-shell access with a server error
SELECT ts, src_ip, path, status FROM events
WHERE source = 'access' AND (path LIKE '%.sh' OR path LIKE '%/cgi-bin/%')
  AND status >= 500
ORDER BY ts;
```

```sql
-- first and last activity of every source IP
SELECT src_ip, min(ts) AS first_seen, max(ts) AS last_seen, count(*) AS n
FROM events WHERE src_ip IS NOT NULL
GROUP BY src_ip ORDER BY first_seen;
```

!!! tip "`extra` inside expressions"
    DuckDB needs `extra->>'key'` **in parentheses** when it is part of an expression, as above —
    or use `json_extract_string(extra, '$.key')`.
