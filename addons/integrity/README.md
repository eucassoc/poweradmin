# Tamper-evident chain for the log tables (demo)

A working sketch for [issue 1900](https://github.com/poweradmin/poweradmin/issues/1900),
"Optional tamper-evident chain for log tables". It is a demo on a fork, made by people who
work on [deedlog](https://github.com/eucassoc/deedlog) (End User Computing Association,
Japan). It is not part of Poweradmin and has not been reviewed by its maintainers.

The issue proposes `logging.integrity_chain`: an HMAC per row, the previous row's hash, and a
console command that verifies the chain. This demo implements that, and adds the one piece an
HMAC chain cannot provide by itself: a reference outside the database.

## The gap

An HMAC chain stops someone who has the database credentials and nothing else. Someone who
also reads the HMAC key (it is in a file the application reads) can rewrite a row, compute a
fresh HMAC, repair every later link, and the verification command passes. Removing rows from
the end leaves a shorter chain that is still valid.

So the chain is checked against a **checkpoint**: the size of the chain and the root hash of
a Merkle tree over its lines, signed by a key the application never sees, and cosigned by a
witness run by someone else. The witness cosigns only if the chain it is shown extends the one
it cosigned before. A rewritten chain cannot get a cosignature, and it no longer matches the
checkpoints that already exist.

| Who | Rewrites a log row | Result |
|---|---|---|
| Has the database credentials | changes the row | `log:verify` fails: the row no longer matches its HMAC |
| Also has the HMAC key | changes the row, repairs the chain | chain and HMACs pass; `log:verify` fails against the cosigned checkpoint |
| Also deletes the stored checkpoints | | `log:verify` fails (none found); a copy kept elsewhere still shows the rewrite |
| Also has the signing key | signs the rewritten chain | the witness refuses to cosign; the two signed checkpoints together prove the rewrite |

## How it works

```
log row ──▶ line in log_integrity_chain ──▶ checkpoint ──▶ bin/poweradmin log:verify
(PHP, in the request)                       (cron, outside the app)   or: dlog verify, offline
HMAC of the row + hash of the line before   signed, then cosigned by a witness
```

- **Line.** After each `INSERT` into a log table, one line is appended to
  `log_integrity_chain`. It holds the HMAC-SHA-256 of the row (its columns as a JSON object)
  and the SHA-256 of the line before it. It does not hold the row's content. Lines are
  [deedlog evidence-chain](https://github.com/eucassoc/deedlog/blob/main/spec/evidence-chain.md)
  records; they are hashed as bytes and never re-encoded.
- **Checkpoint.** `addons/integrity/anchor.sh` exports the chain (hashes only), signs a
  checkpoint with `dlog checkpoint`, has the witnesses cosign it with `dlog cosign`, keeps a
  copy and hands one back to Poweradmin. Checkpoints and cosignatures are the C2SP formats
  (signed-note, tlog-checkpoint, tlog-cosignature, tlog-witness), so any witness that speaks
  them works.
- **Verification.** `bin/poweradmin log:verify` checks, in PHP: every line links to the one
  before; every log row still has the HMAC its line recorded; the chain is the one the
  checkpoint was signed and cosigned for. The exported chain and checkpoint can also be
  checked by anyone with `dlog verify`, without access to Poweradmin.

PHP needs nothing new except `sodium` for checking signatures. The Go tool `dlog` is used
only by the anchoring job.

## Pruning and anonymising

The issue notes that anonymising (issue 1861) or pruning (issue 1172) old rows would need
to re-chain the rows. With this layout it does not: a line holds the row's HMAC, not the row,
so the row can change or go while the line stays. What was done is appended:

- `row.anonymized`: the new HMAC of one rewritten row. The old line stays in the chain; the
  HMAC in it reveals nothing about the removed name without the key.
- `rows.pruned`: "every row of this table with an id up to N was deleted", one line for the
  whole run.

`log:verify` then expects exactly that: the anonymised row with its new content, the pruned
rows absent. A row that disappears without such a line is reported. `log:prune` and
`log:anonymize-user` in this demo are small stand-ins for those two issues, enough to show
the mechanism.

## Settings

All under `logging`, off by default. With `integrity_chain` off, each log write costs one
configuration lookup (measured: about 0.2 microseconds) and nothing else.

| Setting | |
|---|---|
| `integrity_chain` | `false`. Chain every new log row. |
| `integrity_chain_origin` | Name of the chain, a schema-less URL you control, e.g. `dns.example.net/poweradmin-audit`. |
| `integrity_chain_key_file` | File holding the HMAC key (32 bytes or more). Not in the database, not in its backups. |
| `integrity_chain_operator_key` | Verifier key of the checkpoint signer (public). |
| `integrity_chain_witness_keys` | Verifier keys of the witnesses whose cosignature `log:verify` requires. |

## Commands

```
bin/poweradmin log:verify [--checkpoint=FILE] [--operator-key=FILE] [--witness-key=FILE] [--quorum=N] [--chain-only]
bin/poweradmin log:chain-export DIR          # chain.jsonl and the newest checkpoint
bin/poweradmin log:checkpoint-import FILE    # used by anchor.sh
bin/poweradmin log:prune --table=T (--keep-days=N | --before="Y-m-d H:i:s")
bin/poweradmin log:anonymize-user NAME --replacement=deleted-user-ID
addons/integrity/anchor.sh                   # sign, cosign, keep a copy; from cron
```

`log:verify` exits 0 when everything holds and 1 otherwise, naming the table, row id and line.
`--checkpoint=FILE` holds the chain to a copy kept outside the database, which is the stronger
check: a checkpoint stored next to the rows can be deleted with them.

## Questions the issue leaves open, and what this demo does

- **Where the key lives.** Two keys with different jobs. The HMAC key is in a file the
  application reads (`integrity_chain_key_file`). The checkpoint signing key belongs to the
  anchoring job and should be unreadable to the web server's account. Each line names the
  HMAC key it was made with (`key`, a short hash); rows recorded under another key are
  reported as not checked. Rotating keys is not implemented beyond that.
- **Columns.** None are added to the log tables. Two new tables: `log_integrity_chain
  (seq, line)` and `log_integrity_checkpoints (id, size, note, created_at)`.
- **Existing rows.** The first line of the chain records the highest id of each log table at
  that moment. Rows up to it are older than the chain and are reported as not covered.
- **Rows removed from the end.** Caught by the checkpoint: it covers more lines than the
  chain has.

## Try it

Needs PHP with `pdo_sqlite` and `sodium`, Node with Playwright, and `dlog`
(`go install github.com/eucassoc/deedlog/cmd/dlog@latest`). Everything runs locally: SQLite,
PHP's built-in server, a witness on 127.0.0.1. All names and data are made up.

```sh
addons/integrity/demo/run.sh /tmp/integrity-demo
```

It walks through four scenes: normal use with signing and cosigning; a row rewritten with
the database credentials; the same with the HMAC key as well (the chain passes, the
checkpoint does not, the witness refuses, and the rewrite is proven); anonymising and
pruning with the chain intact.

## What this does not do

- It shows that a row has not changed since its line was written and that the chain has not
  changed since it was cosigned. It does not show that what the row says is true.
- A compromised application can write false rows from then on; they are chained like any
  other. It cannot change what was already cosigned.
- Rows written after the last cosigned checkpoint are protected by the HMAC key only. How
  often the anchoring job runs is how much that is.
- A witness sees the chain's size and root hash, and the time. It does not see rows, lines,
  users or zones. A witness run by the same people as the database protects little.
- deedlog is before v1.0; its formats can still change.

## Tested, and not

Tested here: the demo script end to end on SQLite with PHP 8.3, and the exported chain and
checkpoints against `dlog verify`.

Not tested: MySQL and PostgreSQL (the schema files are extended; the update scripts and the
installer's structure helper are not); concurrent writers (two requests that read the same
last line: the loser retries on the primary-key conflict, which inside an open PostgreSQL
transaction would need a savepoint); large tables (`log:verify` reads the whole chain into
memory); the project's own test suite, PHPStan and PHPCS, which were not run.
