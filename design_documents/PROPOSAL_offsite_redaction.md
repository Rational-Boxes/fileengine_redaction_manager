# Proposal: redacting content from the offsite backup, with a human in the authorisation path

**Status:** **Captured for the future — not scheduled, not a priority.** Nothing
implemented, and nothing here is waiting on a decision. It is written down now
because the reasoning is fresh: the gap was found while changing the restore
(see the companion below), and a design worked out at the moment the problem is
understood is worth more than one reconstructed later from a one-line note.

Pick it up when a redaction has to be *guaranteed* rather than *effective* —
a subject-access erasure the organisation has undertaken to complete, a
contractual redaction, content that must not exist. Until then the platform's
honest position is §1's: an erased file is unreachable and unrestorable, which
is enough for most purposes and is not the same as gone.
**Scope:** a **new single-purpose application on the backup account** (§5 — the
substantial deliverable, and a repo of its own),
`provisioning/aws/backup-buckets` (the IAM role and the policy edit it needs),
`roles/backups` (emit the request), `file_engine_core` (nothing, unless §6 is
taken instead), process (the part that matters)
**Companion:** [RESTORE.md](RESTORE.md) § *Restore the file content*, which
stops erased payloads becoming live again but does not destroy them, and records
that limitation as a known gap. This is the proposal to close it.

---

## 1. The problem, stated exactly

Erasure destroys a file's version rows, deletes the payload from local storage
and from the **live** object store, and fails the whole operation loudly if that
delete does not succeed — `filesystem.cpp`'s own comment is that "an erasure that
left content in the bucket has erased nothing while reporting that it has".

It cannot reach the offsite copy. The content bucket's policy denies
`s3:DeleteObjectVersion` to everyone but a break-glass role and the account root
(`bucket-policy-protect-history.json`), the mirror runs with no `--remove`, and
versioning is enabled — so every payload ever mirrored is still there, in every
version, permanently.

**That is the correct design and it should not be weakened.** The offsite copy
exists so that losing the droplet, the DO account, or control of either does not
lose the data. A backup a compromised production host can delete from is not a
backup. The moment `s3:DeleteObject` is available to anything the deployment
holds, ransomware has it too.

So the platform is in a position where it can honestly say an erased file is
**unreachable and unrestorable**, and cannot say it is **gone**. For most
purposes the first is enough. For a deletion the organisation has undertaken to
perform — a subject-access erasure, a contractual redaction, content that must
not exist — it is not.

---

## 2. The idea

A **redaction service on the backup account**, driven by a human who is logged
into that account and nowhere else.

1. The deployment produces a **redaction request**: a file listing what it
   believes must be destroyed, with the evidence for each item.
2. **An administrator carries it across.** They download it, read it, and upload
   it into the redaction application themselves. There is deliberately **no
   automated path** from the deployment into that application — see §5.1. A copy
   also lands in the meta bucket, but as evidence, not as an input queue.
3. An administrator signs in to the backup account — a different cloud, a
   different identity provider, credentials that have never been on the droplet
   and are not in the deploy vault — reviews the request, and approves it.
4. Only then does anything delete, and only what was approved.

**The human is not a procedural formality; they are the authorisation
boundary.** Everything else in this design exists to make their judgement
possible, because a reviewer who cannot meaningfully check what they are
approving is a rubber stamp with a salary.

---

## 3. Why this is the right shape

The property to preserve is: *nothing the deployment holds can destroy the
offsite copy.* A service on the backup account that acts on a file the
deployment wrote would break that immediately — the deployment would have
acquired a deletion capability, just with extra steps.

It is preserved here because the request carries no authority. It is a claim,
evaluated on the far side, by a principal the near side cannot become. A
compromised droplet can write any request it likes; it cannot approve one.

The provisioning already anticipates this. `OnlyTheBreakGlassRoleMayDestroyHistory`
names a `BREAK_GLASS_ROLE` as the sole non-root principal permitted
`s3:DeleteObjectVersion`. **The role exists; what is missing is a workflow that
makes using it safe and routine enough to actually happen** — and a break-glass
credential nobody has rehearsed using is one nobody will use correctly under
pressure.

---

## 4. What makes the review real

A reviewer handed a CSV of ten thousand opaque UUIDs will approve it. The design
has to make approval *checkable*, or the human is theatre.

### 4.1 The request carries evidence, not just keys

Each row: `erasure_id`, `tenant`, `file_uid`, the object key prefix, the actor
who erased it, the reason, and `initiated_at`. The erasure table retains all of
it — deliberately, since "the payload is destroyed; the fact is retained".

### 4.2 The backup account verifies against its own records, not the request

This is the part that gives the human something to stand on.

The meta bucket already holds the database dumps, including the **hash-chained
accountability records**. It is append-only to the same degree the content
bucket is. So the redaction service can check each `erasure_id` against a chain
copy **that the deployment cannot alter, because it was uploaded before the
request and cannot be deleted**:

- does this `erasure_id` appear in a retained chain?
- does that chain verify end to end?
- do the actor, reason and timestamp match the request?

A compromised droplet can forge a request. It cannot retroactively forge the
evidence for it, because the evidence is already in a bucket it cannot rewrite.

**What this does not stop, and the proposal should not pretend otherwise:** an
attacker with the core can perform *genuine* erasures and then request their
redaction. The chain will verify, because the erasures really happened. Volume
limits, the hold period and the human are what address that; cryptographic
verification is not.

### 4.3 Volume is the signal

A normal redaction is a handful of files. Thousands is not a busy week, it is an
attack or a bug.

- Requests above `redaction.max_objects` (suggest **50**) are refused outright
  and require a second, separately-authorised approval.
- Requests above `redaction.max_per_window` in a rolling window are refused.
- The service reports the number **before** anything else, in the first line a
  reviewer sees.

### 4.4 A hold period

Approved requests execute after `redaction.hold_days` (suggest **7**), during
which they are visible and cancellable. A statutory erasure deadline is
typically a month, so a week costs nothing and turns a silent compromise into
something with a window to notice it in.

Skipping the hold is possible, requires a distinct authorisation, and is
recorded as having been skipped.

---

## 5. The application

This is a **new application, built for this and nothing else**, running on the
backup account. It is the substantial deliverable here; §4 is what it has to
implement and §7 is what it costs.

Single purpose is a security property rather than a matter of taste. It will
hold — briefly, at operation time — the only credential in the estate that can
destroy backup history. Every feature that is not redaction is more code within
reach of that credential, and more reason for someone to log in for a task that
is not this one. It gets no general admin surface, no reporting, no account
management, no shared runtime with anything else.

### 5.1 It has no inbound path from the deployment

The deployment writes a request; it does not deliver one. The application takes
its input from the **administrator's upload**, not from a bucket it polls.

The difference matters more than it looks. An application that ingests from the
meta bucket has an automated channel from cloud A to the one thing that can
delete from cloud B — and then the human is reviewing a queue rather than
standing in the path. Making the human carry the file means a compromised
deployment has no route to the redaction application at all: not a slow one, not
a rate-limited one, none. What it can do is produce a request that nobody
collects.

The meta-bucket copy is still written, because the evidence trail should exist
independently of whether anyone acts on it.

### 5.2 It is on-demand, not always-on

It runs for the operation and stops. A long-lived service with a path to
`DeleteObjectVersion` is a standing risk in exchange for convenience nobody
needs — redactions are rare and scheduled, not interactive.

It also does not hold the break-glass credential. It assumes the role at
operation time through STS, MFA-required, with a short session, so the window in
which the capability exists at all is the window in which it is being used.

### 5.3 What it does

- Accepts an uploaded request file and shows its **size first** (§4.3).
- Verifies each `erasure_id` against the retained accountability chain in the
  meta bucket (§4.2), and refuses to display any row it could not verify as
  approvable — an unverifiable row is the one a reviewer would skim past.
- Presents the request for approval, per row, with the evidence beside it.
- Holds the approved set for `redaction.hold_days` (§4.4), visible and
  cancellable.
- On execution, deletes every version of every key under each approved
  `<tenant>/<file_uid>/` prefix, reports per key, and treats a surviving version
  as a failure rather than a warning.
- Writes its ledger to the meta bucket and leaves CloudTrail as the independent
  record.

### 5.4 What it deliberately does not do

- **Not delete anything not on an approved list.** No wildcards, no prefix
  sweeps, no "and everything under this tenant".
- **Not accept a list it assembled itself.** It has no query path into the
  deployment; the request comes from outside it.
- **Not run unattended, ever** — including the execution after the hold period,
  which requires a human to return. An unattended executor is an automated
  deletion path with a delay on it.
- **Not hold long-lived credentials**, and not run in the same account as
  anything else that matters.

## 6. Mechanics

**Request.** `fileengine-backup.sh --redaction-request` emits
`redaction-<ts>.csv` from the erasure tables and uploads it under
`meta/redaction/pending/`. The mirror credential can already write there; it
needs nothing new. Emitting the request must **not** require any delete
permission anywhere.

**Execution.** Deleting one object means deleting *every version* of it
(versioning is on), which is `DeleteObjectVersion` against each version id of
each key under `<tenant>/<file_uid>/`. Partial success is failure: the service
reports per key, and a key with a surviving version is an unredacted key.

**Proof.** After execution, list all versions of each key and expect none. Write
the result to `meta/redaction/completed/<ts>.txt` — in the same bucket, so the
record of the destruction is as durable as the thing destroyed was, and
CloudTrail holds the independent copy.

**Feeding it back.** The deployment's erasure record should be able to say the
offsite copy was destroyed and when. The `erasure_ack` table already models
exactly this — participants acknowledging compliance, with `complied = false`
recorded rather than silence — so the backup account becomes another
participant. That is a small change and it makes `ListPendingErasures` tell the
truth about the whole system rather than about the deployment only.

---

## 7. The alternative: destroy the key, not the bytes

Worth stating because it is strictly better where it applies, and because the
hook for it now exists.

If each file's payload were encrypted under its **own** key, erasure would be
the destruction of that key. The payload would become unreadable everywhere at
once — live bucket, offsite bucket, every backup set, every copy anyone ever
took, including immutable ones — **with no delete permission anywhere and no
human in the loop**. Crypto-shredding is how systems that genuinely cannot
delete from their own backups solve this.

The platform encrypts under one deployment-wide key (`AT_REST_KEY`), so this is
not available today. But the storage pipeline work has just added `key_id` as a
version column and as a field in the v2 storage header
(`file_engine_core/design_documents/storage_pipeline.md` §6.2), which is the
seam: a version already records which key it was written under, and the reader
already takes that from the blob.

Two honest limits:

- **It only protects content written after it is adopted.** Everything already
  in the offsite bucket is under the deployment key and stays that way. So
  crypto-shredding is the answer for the future and §2–§6 is still the answer
  for the past — they are complementary, not alternatives.
- **Key management becomes the hard part**, and a key store that the deployment
  can delete from has the same problem one layer down. The keys would need the
  same treatment: destroyed on the far side, by a human, with the deployment
  able to request and not to act. The advantage is that a key is a few bytes and
  a handful of them can be reviewed properly, where ten thousand object keys
  cannot.

**Recommendation:** treat §7 as the direction and §2–§6 as the thing to build
now. A redaction capability that only works for files created after a future
migration does not answer the request that arrives next month.

---

## 8. What this costs

- **The application itself** (§5), an IAM role, and a policy change on the
  backup account —
  the last being the single most dangerous edit in this document, since it is
  what makes destruction possible at all. It should be the hardest change to
  make and the easiest to audit.
- A break-glass credential that is **rehearsed**, or it will not work when
  needed. Add it to the restore-rehearsal cycle: the rule already in
  RESTORE.md's known gaps — rehearse whenever the set of backed-up things
  changes — covers this too.
- An administrator who is genuinely separate. If the same person holds the
  droplet's root and the backup account's break-glass role, the firewall is
  organisational fiction. That is a staffing decision this document cannot make,
  and it is the assumption everything above rests on.

---

## 9. Open questions

**Q1 — Who is the administrator?** §8's last bullet. Everything here assumes a
principal genuinely separate from deployment operations, and that assumption
should be tested against who actually exists before the workflow is built around
it.

**Q2 — Does the meta bucket's retention outlive the content bucket's?** §4.2
depends on a chain copy older than the request being available. If meta sets age
out faster than content, the verification has a window it does not survive.

**Q3 — Object Lock.** Not currently configured. Compliance-mode lock would make
§6 impossible even for root, and would force §7. Governance mode would leave
this design intact. Worth deciding deliberately rather than by default, because
turning it on later is easy and turning it off is not.

**Q4 — Should redaction be per-file or per-subject?** A subject-access erasure
names a person, not a file uid. Resolving one to the other is the deployment's
job and it is not obviously reliable — worth knowing whether the request should
carry the subject as well, so the reviewer can see what was claimed rather than
only what was resolved.
