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

- the archive and live SEP each contain two identity records, and their UUID
  sets match exactly;
- the archive contains one distinct entity number whose group contains both
  records;
- requested and effective protected policy both equal `(1, 1, 1, 0)`;
- the T2 reports maximum count 5 and free count 1;
- version-0 Catacomb UUID, state, and group queries all reject with the same
  bridge status even though the identities are usable for matching; and
- mutation and persistence readiness remain deliberately false.

The entity number is structural metadata. It must not be presented as a
general count of user-visible fingerprints. The two records in the current
entity also do not have identical names or creation times, so collapsing them
into one ordinary identity object would discard Apple-owned state.

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
- two UUIDs added and none removed.
- master, selected-user, and bio-lockout component files all changed.

The same live T2's free counter was 3 before that interval and is now 1.
Together these independent deltas show that the capture interval consumed two
identity units and created two UUID records under one entity on this firmware.
The two private records' creation times are about eight minutes apart, which
is consistent with the separate complete and cancelled capture runs. That is
supporting evidence for cancellation residue, not proof of which run owns
either record.
They do **not** distinguish a two-record representation of the completed
fingerprint from residue associated with the cancelled attempt. The macOS UI
shows one fingerprint, but that is not enough to assign either private record
to a particular operation. They also do not establish that another T2 model or
bridgeOS build uses the same representation.

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

The clean fixture is encrypted on EFI but has not yet been imported or compared
with the live T2 from Linux. A Linux enrollment experiment is therefore not
justified until the Linux thread validates the fixture, preserves the current
two-record rollback state, imports the clean archive atomically, and confirms
host/live identity and capacity agreement without resetting the sensor. The old
zero-state attempts had enough reported capacity but command 3 returned a
synchronous rejection before sensor capture, so finger placement was not
involved.

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

Until those gates are implemented and offline-tested, the baseline reports
`safe_for_mutation=false`. Existing authentication remains untouched and is
the recovery control.

## Clean macOS enrollment result

The controlled macOS pass completed on build `25G83`. Its validated zero state
contained no identity records. Exactly one completed enrollment then produced
one identity record, one entity number with group size one, a master enrollment
count delta of one, and changes to all three Catacomb components. The final
23,562-byte encrypted fixture passed CMS parsing, retained no raw values, and
left no plaintext behind. Full sanitized evidence is recorded in
`docs/macos-clean-enrollment-fixture-handoff.md`.

The next controlled discriminator is the Linux return plan from that handoff:
validate and adopt the clean fixture with the two-record state preserved as
rollback evidence, compare it with stable live state and capacity without a
sensor reset, and keep `safe_for_mutation=false` until every persistence,
journal, password-fallback, and rollback gate passes.
