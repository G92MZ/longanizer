# Query language

The Explorer search box speaks one query language — the same in Longanizer and WinHound.
Field names and values ignore case.

## Field operators

The two to remember:

| | Means | Example |
|---|---|---|
| `field=value` | **equal** — the exact value | `user=root` (skips `root2`) |
| `field:value` | **contains** | `exe:wget` |

**Number fields are always exact**, with either operator: `status`, `pid`, `src_port`, `bytes` and
`line_no`. So `status:40` never matches 404. Spaces around the operator are fine:
`status = 404`, `user: root`.

| Syntax | Means | Example |
|---|---|---|
| `field!=value` | not equal (same as `-field=value`) | `user!=root` |
| `field>N` `>=` `<` `<=` | compare numbers and dates | `status>=500` · `ts>=2026-10-01` |
| `field=a,b,c` | any of several numbers | `status=404,500` |
| `field:*x*` | wildcards `*` and `?` over the whole value | `user_agent:*curl*` · `status:4*` |
| `field:/regex/` | regular expression on one field | `exe:/wget$/` · `src_ip:/^203\./` |
| `field:*` | the field has a value | `src_ip:*` |
| `field:-` | the field is empty or missing | `user:-` |
| `ts:2026-10-01` | a whole day (dates match by prefix) | `ts:2026-10-01 status>=400` |
| `field contains value` | word form of `:` | `src_ip contains 203` |
| `field==value` | synonym of `=` (kept for old searches) | |

`=` takes the value literally — in access logs, `referer=-` finds the literal `-`. Wildcards and
regex need `:`.

## Free text and combining

| Syntax | Means |
|---|---|
| `suid bash` | free text: both words appear (AND) |
| `"Failed password"` | a literal phrase; quotes also let you search the words *and*, *or*, *not* |
| `/invalid.user/` | a regular expression over the raw line |
| `a AND b` · `a b` | AND (the default) |
| `a OR b` | OR |
| `NOT a` · `-a` | NOT |
| `( … )` | grouping |

`AND`, `OR` and `NOT` are case-insensitive (`&&`, `||` and `!` work too). Examples:

```text
(Failed OR Accepted) user=root NOT src_ip:10.
event=ssh_failed src_ip:203. -user=root
source=access status>=500 path:*.sh
exe:/wget|curl/
/failed|invalid/
```

Free text searches the message, the raw line, `exe`, `path`, `user`, the IP, the program and the
source.

## Field names

Field names ignore case, `_`, `-` and `.`, and common names work:

| You type | Field |
|---|---|
| `ip` · `client_ip` · `rhost` · `addr` | `src_ip` |
| `port` · `sport` · `dport` | `src_port` |
| `ua` · `UserAgent` | `user_agent` |
| `url` · `uri` · `request` | `path` |
| `code` · `status_code` | `status` |
| `level` · `sev` · `priority` | `severity` |
| `prog` · `process` · `service` | `program` |
| `username` · `account` | `user` |
| `hostname` · `computer` | `host` |
| `msg` | `message` |
| `size` · `length` | `bytes` |
| `type` · `eventtype` | `event` |
| `time` · `timestamp` | `ts` |

**Keys of the `extra` JSON** (auditd, logfmt, CSV) work by name too: `comm:wget`,
`key:exec_watch`. `x:key` (or `extra.key`) forces an `extra` key with its exact case. The full list
of columns is in the [data model](data-model.md).

## Mistakes are reported

- An **unknown field** shows a ⚠ warning and is searched as plain text, instead of returning
  nothing in silence. Paths and URLs (`http://203.0.113.55/x.sh`) are plain text without a warning.
- A **malformed query** — an unclosed quote or parenthesis, `OR` at the end, `status=` with no
  value — says what is wrong.

The **regular expression** checkbox turns all of this off and treats the whole box as one regex
over the raw line (`^` and `$` anchor to the line).

## From the results

- **⊕ / ⊖** on any cell, or **Ctrl/⌘-click** (with **Shift** to exclude), adds `field=value`
  (or `-field=value`) to the query.
- A **facet** value adds `field=value` too.
