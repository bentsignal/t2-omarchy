# macOS handoff: clean one-enrollment fixture

This is a one-machine, two-OS handoff. The Linux and macOS Codex threads do not
run concurrently. The macOS thread must fetch GitHub `main`, read the repo's
cross-OS discovery skill and this document, perform only the bounded procedure
below, commit its sanitized result here, push, and tell Shawn to boot Linux.

## Why this pass is needed

The current macOS UI lists one fingerprint, but the validated host archive and
live SEP contain two identity UUID records sharing one entity number. Those
records were created across an interval containing one complete enrollment and
a separate first accepted scan followed by cancellation. Their creation times
are about eight minutes apart. The second record may therefore be residue from
the cancelled capture rather than a required two-record representation of one
finger.

That ambiguity blocks Linux-native enrollment recovery and capacity policy.
The T2 currently reports only one free identity unit. We need one exact
zero-state to one-completed-enrollment transition with no partial attempt in
between.

## Authorized macOS procedure

Shawn explicitly controls both visible fingerprint mutations in System
Settings. The helper only freezes `biometrickitd` long enough to snapshot its
three Catacomb files, validates those private snapshots, compares redacted
shape deltas, and encrypts the final clean snapshot to the existing EFI public
certificate.

From the updated repository root, run:

```bash
sudo tools/research/capture-macos-clean-enrollment-fixture.sh
```

The helper will:

1. validate and privately snapshot the current nonempty starting state;
2. ask Shawn to remove every visible fingerprint in System Settings;
3. require a strictly valid zero-identity Catacomb before continuing;
4. ask Shawn to complete exactly one new fingerprint enrollment and not begin
   another attempt;
5. validate the resulting archive and require an exact zero-to-nonzero UUID
   addition with no removal;
6. encrypt only the final archive to
   `/Volumes/EFI/t2-touchid-catacomb-clean-single.cms`; and
7. delete every plaintext snapshot and comparison file before printing one
   sanitized JSON line.

If deletion leaves a nonzero hidden identity inventory, the helper stops before
the new enrollment prompt. If enrollment or validation fails, restore one
working fingerprint through normal macOS Settings before leaving macOS. Do not
improvise a Linux-side identity deletion or Catacomb rewrite.

Never print or commit Catacomb bytes, identity names, UUIDs, hashes, absolute
timestamps, credentials, sensor events, raw logs, or temporary paths. Commit
only the final sanitized JSON fields: counts, entity-group sizes, count deltas,
component-changed Booleans, build, CMS byte length, CMS parse success, and
plaintext removal.

## macOS result

Pending.

## Linux return plan

The Linux thread will fetch and review the committed sanitized result, verify
the new CMS exists, decrypt it only in a root-owned mode-0700 temporary
directory on the encrypted Linux filesystem, independently validate it, and
atomically preserve the existing two-record archive before adopting the clean
fixture as `catacomb-pre-clean-enrollment-backup`; the original
`catacomb-zero-identity-backup` remains untouched. The read-only baseline can
validate the decrypted tar archive directly against the stable live inventory
before the importer commits anything. It will then compare live capacity
without resetting the sensor.

No Linux enrollment command will run until the clean identity delta, available
capacity, host/live equality, password fallback, journal, three-component save,
and rollback gates all pass.
