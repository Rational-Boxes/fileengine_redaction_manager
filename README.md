# redaction_manager

> ⚠️ **Scaffold only.** The design is captured and unscheduled; no capability is
> implemented. `/readyz` is red without credentials in the environment, and that
> is the safe direction — with none, nothing can be destroyed.

The application that **destroys approved payloads in the offsite backup**, on
the backup account, with a human in the authorisation path.

Read [`design_documents/PROPOSAL_offsite_redaction.md`](design_documents/PROPOSAL_offsite_redaction.md).

## Why this exists

Erasure destroys a file's version rows, its local bytes and its payload in the
**live** object store, and fails loudly if it cannot. It has no way to reach the
offsite copy: that bucket denies `s3:DeleteObjectVersion` to everything but a
break-glass role, the mirror runs with no `--remove`, and versioning is on — so
every payload ever mirrored is still there.

**That is correct and must not be weakened.** A backup a compromised production
host can delete from is not a backup. So the capability lives here, on the far
side, where the deployment cannot reach it.

The platform's honest position until this is built: an erased file is
**unreachable and unrestorable**, not gone.

## The four properties that govern every change here

1. **No route to the deployment.** Not a queue, not a webhook, not a polled
   bucket. Its input is a file an administrator carried here. A fully
   compromised deployment can produce any request it likes and nobody collects
   it.
2. **Single purpose.** It briefly holds the only credential in the estate that
   can destroy backup history. Every feature that is not redaction is more code
   within reach of that credential.
3. **On demand.** It runs for the operation and stops. Credentials come from
   the environment and end with the process — export them for the operation,
   and do not persist them in a dotfile, in shell history, or in a `.env` that
   outlives the afternoon.
4. **Never unattended** — including execution after the hold period. An
   unattended executor is an automated deletion path with a delay on it.

The dependency list is part of this, not incidental to it: `grpcio`, `ldap3`,
`redis` and `psycopg` are absent deliberately, and a test asserts their absence
so "no route to the deployment" is structural rather than aspirational.

## The procedure it serves

The administration application raises the signal, an administrator confirms with
the end customer, approves, and **carries the request here**. Then: verify each
`erasure_id` against the retained accountability chain, show the volume before
the rows, hold for the cooling period, execute, and prove it — listing every
version of each key and expecting none.

## Known design gaps

- **The return path.** The administrator should carry the completion receipt
  back too; otherwise an automated channel is reintroduced in the other
  direction. Until settled, `ListPendingErasures` cannot tell the truth about
  the whole system.
- **How chain evidence reaches here in a verifiable form.** §4.2 requires
  checking requests against the retained chain, and the meta bucket holds
  database dumps. Verifying a hash chain from a `pg_dump` means loading it
  somewhere — so either this tool loads a dump locally, or the deployment
  exports a purpose-built chain manifest. Not decided.

## Develop

```bash
pip install -e ".[dev]"
cp .env.example .env
pytest src/tests -q
redaction-manager            # loopback review UI; stop it when the operation ends
```

## License

Copyright (C) 2026 James Hickman <james@rationalboxes.com>

Licensed under the **GNU Affero General Public License, version 3 (or later)** —
see [LICENSE](LICENSE).
