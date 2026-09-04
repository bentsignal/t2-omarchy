# T2 Touch ID native-enrollment checkpoint

This is the current safety and evidence boundary for enrolling a fingerprint
from Linux on the tested `MacBookPro16,1`, bridgeOS `23P6068`. Authentication
already works after a complete shutdown; this document covers only creation
and durable persistence of a new fingerprint without macOS.

No command described as a baseline or comparison here starts enrollment,
requests a touch, changes protected policy, resets the sensor, loads a
Catacomb, or prints a biometric identifier.

## Current read-only baseline

`prototypes/t2sep-probe/native-enrollment-baseline.py` now validates the
root-only current Catacomb and compares its private UUID set internally with
two byte-identical live SEP identity reads. Its public result contains only
counts, Boolean relationships, and status codes.

On the tested machine it established all of the following:

- the archive and live SEP each contain one identity record, and their UUID
  sets match exactly;
- the archive contains one distinct entity number with group size one;
- requested and effective protected policy both equal `(1, 1, 1, 0)`;
- the T2 reports maximum count 5 and free count 2;
- version-0 Catacomb UUID, state, and group queries all reject with the same
  bridge status even though the identities are usable for matching; and
- mutation and persistence readiness remain deliberately false.

The entity number is structural metadata. It must not be presented as a
general count of user-visible fingerprints. The previous two-record archive
is preserved separately because its reused entity was valid Apple-owned state,
not something an importer may deduplicate.

Run the baseline only while the installed operation lock is available:

```bash
sudo python3 prototypes/t2sep-probe/native-enrollment-baseline.py \
  --live --apple-user-id 501 \
  --confirm=I_UNDERSTAND_THIS_ONLY_READS_NATIVE_ENROLLMENT_BASELINE
```

## Proven enrollment-capture interval

The root-only zero-identity backup predates the macOS capture interval. That
interval contained one completed fingerprint enrollment and a separate
accepted first scan followed by cancellation. The current archive is the
later state. The privacy-safe comparison tool reports:

- identity records: 0 to 2;
- distinct entity numbers: 0 to 1;
- the new entity group size: 2;
- master enrollment count: 1 to 3;
- two UUIDs added and none removed;
- master, selected-user, and bio-lockout component files all changed.

The same live T2's free counter was 3 before that interval and is now 1.
Together these independent deltas show that the capture interval consumed two
identity units and created two UUID records under one entity on this firmware.
The two private records' creation times are about eight minutes apart, which
is consistent with the separate complete and cancelled capture runs. That is
supporting evidence for cancellation residue, not proof of which run owns
either record.
The later controlled clean enrollment distinguishes these cases: one completed
enrollment creates one record, while the earlier interval's additional record
was residue from its separately accepted then cancelled attempt. These results
still do not establish that another T2 model or bridgeOS build uses the same
representation.

The comparison is reproducible without printing either UUID:

```bash
sudo python3 tools/research/catacomb-identity-shape-delta.py \
  /var/lib/t2-touchid/catacomb-zero-identity-backup \
  /var/lib/t2-touchid/catacomb \
  --apple-user-id 501
```

## Consequences for Linux enrollment

The clean macOS transition now proves that one uninterrupted completed
enrollment on this `MacBookPro16,1` adds exactly one SEP identity, creates one
one-member entity group, increments the master enrollment count by one, and
changes all three Catacomb components. The extra record in the earlier interval
is attributable to its separate accepted-then-cancelled attempt. Existing
archives must still accept reused entity numbers so that recovery can preserve
that historical Apple-owned state without deduplicating it.

Linux independently decrypted and validated the clean fixture, proved its
private identity set exactly matched two stable live T2 reads, and atomically
adopted it. The previous two-record store is preserved as
`catacomb-pre-clean-enrollment-backup`, while the original zero-identity backup
remains untouched. Post-import validation proved the installed components are
byte-identical to the fixture. The live T2 now reports two free identity units.

The old zero-state attempts had enough reported capacity but command 3 returned
a synchronous rejection before sensor capture, so finger placement was not
involved. A populated-state attempt must never issue `NoCatacomb` merely
because optional version-0 state queries reject; a stable nonempty identity
inventory is the authoritative presence gate.

Before the mutation gate can open, an independent Linux implementation must:

1. preserve any preexisting reused-entity representation rather than
   deduplicating Apple-owned state;
2. require exactly one added identity and one added entity for an uninterrupted
   completed operation on this bridgeOS generation;
3. transactionally save all changed Catacomb components and atomically update
   the host keyed archives;
4. reconcile terminal disconnects and every partial persistence state against
   both the live SEP and the previous root-only backup; and
5. prove at least one free identity unit immediately before mutation.

The transaction and rollback gates are now implemented and offline-tested as
described below. Existing authentication remains untouched and is the recovery
control until one supervised end-to-end enrollment proves the live save order.

## Clean macOS enrollment result

The controlled macOS pass completed on build `25G83`. Its validated zero state
contained no identity records. Exactly one completed enrollment then produced
one identity record, one entity number with group size one, a master enrollment
count delta of one, and changes to all three Catacomb components. The final
23,562-byte encrypted fixture passed CMS parsing, retained no raw values, and
left no plaintext behind. Full sanitized evidence is recorded in
`docs/macos-clean-enrollment-fixture-handoff.md`.

The Linux return completed successfully. Independent Python plist validation
accepted the archive after macOS Foundation validation, the clean identity
matched stable live state, the protected policy remained exact, and free
capacity rose from one to two. The installed store matches the fixture with no
component delta. `safe_for_mutation=false` remains correct until every
persistence, journal, password-fallback, and rollback gate passes.

## Linux three-component transaction implementation

The MIT prototype now has an independent offline implementation of the missing
host transaction:

- command `0x4a`, version 1, is encoded as the bounded bio-lockout save and its
  response must be a 16-to-4096-byte `HRLB` record;
- a completed enrollment saves selected-user and master `LTFC` payloads through
  prepare/complete/confirm, staging each payload durably before its SEP host
  confirmation, then captures bio-lockout;
- the host keyed archives gain exactly one new private identity with the first
  unused entity number, increment the master enrollment count once, and replace
  all three secure payloads;
- the journal stores only counts, lengths, and SHA-256 digests; the raw terminal
  identity and opaque SEP data remain in root-only staging files;
- the complete candidate is independently schema-validated before commit, the
  previous store is retained as rollback evidence, and a failed directory swap
  restores the previous store; and
- successful commit removes the raw identity and secure-payload staging files.

Privacy-safe comparison of the preserved zero, historical two-record, and
clean one-record stores proved that the secure payload itself changes in all
three components. This is stronger than the earlier whole-file comparison and
rules out treating bio-lockout as optional metadata.

The real one-finger store passed a fully isolated transaction dry run: identity,
entity, and master counts each advanced by exactly one, the final journal phase
was committed, private staging was removed, and the installed live store was
not modified. The complete public suite passes 484 prototype tests and 114
research tests, with one expected macOS-only skip.

The live gate remains explicit. The next step is a no-touch preflight against a
baseline archive matching the clean store, followed by one supervised new-finger
enrollment. No repeat is allowed after an ambiguous post-dispatch failure;
journal and live/host reconciliation take precedence.

That no-touch preflight subsequently passed. The previously active baseline
archive was retained under a private historical directory, a new hash-named
archive was generated from the independently validated clean store, and the
broker reported one host/live identity, available capacity, a verified local
store, same-connection inventory, and initialized retained sensor state. It
reported `mutation_performed=false`. The next action is therefore the single
supervised new-finger enrollment, not another macOS pass or discovery probe.

The first supervised populated-state start accepted the password and command 3,
then stopped on its first callback before a scan was accepted. The callback was
the already characterized version-1 SKS lock-state auxiliary event: this T2 can
emit its 22-byte system-scoped UID-0 form after enrollment starts, while the
broker accepted UID 0 only during prestart staging and required UID 501 in the
active reducer. Fresh host/live reconciliation proved one unchanged identity,
no persistent delta, and no remaining unfinished operation.

`tools/research/run-external-enrollment-overlay.py` pins the exact external GPL
source commit and protocol-module digest, then makes the narrow correction at
runtime without modifying that checkout: the existing event parser still
requires version 1 and a complete six-byte UID/state prefix, and the reducer
accepts only system UID 0 or the pinned enrollment UID. Every other user and
every malformed shape still fail closed. Three focused overlay tests, all 114
research tests, the external broker's 343 tests, and another real no-touch
preflight pass.

The supervised retry passed the system-scoped SKS callback, then stopped on
well-formed version-1 generic status 90. Reconciliation again proved the
one-identity baseline unchanged and cleared the unfinished operation. Apple's
enrollment operation forwards unhandled lower statuses to its generic
operation superclass; the recovered superclass switch leaves status 90 as a
no-op. The pinned overlay now mirrors only that exact behavior after the
underlying reducer has already validated event framing, operation and
connection identity, monotonic ordering, duplicate exclusion, payload shape,
and active cancellation state. Neighboring unknown statuses remain rejected.
Six overlay tests, 117 research tests, 484 prototype tests, the external
broker's 343 tests, and a fresh no-touch hardware preflight all pass.

The next trial reached a touch and stopped at status 63. Reconciliation proved
one unchanged identity with no persistent identity delta. The recovered Apple
generic-operation callback explicitly maps 63 to presence true and 64 to
presence false. The wrapper now accepts those notifications and the paired
90/91 lifecycle events without advancing enrollment or sending continue.
It also stops routing arbitrary enrollment errors to the matching rejection
toast. Versioned evidence, implementation limits, and tests are recorded in
[Enrollment presence callbacks](touch-id-enrollment-presence-events.md).
