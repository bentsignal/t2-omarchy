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

## Proven one-enrollment archive transition

The root-only zero-identity backup is the host state captured before Shawn
added the one fingerprint currently visible in macOS. The current archive is
the matching post-enrollment state. The privacy-safe comparison tool reports:

- identity records: 0 to 2;
- distinct entity numbers: 0 to 1;
- the new entity group size: 2;
- master enrollment count: 1 to 3;
- two UUIDs added and none removed.
- master, selected-user, and bio-lockout component files all changed.

The same live T2's free counter was 3 before that enrollment and is now 1.
Together these independent deltas show that this successful macOS enrollment
consumed two identity units and created two UUID records under one entity on
this firmware. They do not establish that every T2 model or bridgeOS build
uses the same representation.

The comparison is reproducible without printing either UUID:

```bash
sudo python3 tools/research/catacomb-identity-shape-delta.py \
  /var/lib/t2-touchid/catacomb-zero-identity-backup \
  /var/lib/t2-touchid/catacomb \
  --apple-user-id 501
```

## Consequences for Linux enrollment

The earlier MIT prototype and the current upstream GPL reference both model a
successful enrollment as exactly one added SEP identity and create one host
identity object. The upstream decoder also rejects reused entity numbers.
Those assumptions are incompatible with the validated Apple archive on this
`MacBookPro16,1` and must not be used to mutate it.

The current free count is one, while the only proven successful enrollment on
this machine consumed two units. A populated-state enrollment experiment is
therefore not justified merely because the counter is nonzero. The old
zero-state attempts had enough reported capacity but command 3 returned a
synchronous rejection before sensor capture, so finger placement was not
involved.

Before the mutation gate can open, an independent Linux implementation must:

1. preserve the two-record entity representation rather than deduplicating it;
2. accept terminal enrollment evidence only when the complete post-operation
   identity delta is proven for this bridgeOS generation;
3. transactionally save all changed Catacomb components and atomically update
   the host keyed archives;
4. reconcile terminal disconnects and every partial persistence state against
   both the live SEP and the previous root-only backup; and
5. prove sufficient capacity for the expected multi-record operation.

Until those gates are implemented and offline-tested, the baseline reports
`safe_for_mutation=false`. Existing authentication remains untouched and is
the recovery control.
