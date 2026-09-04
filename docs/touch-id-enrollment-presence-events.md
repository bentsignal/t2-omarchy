# Enrollment presence callbacks

## Observed Linux failure, 2026-09-04

After the status-90 overlay, the supervised enrollment accepted password
binding (`verify-password-acm: status=0`) and reached the user's touch. The
reducer then froze on generic status **63**. Fresh reconciliation found one
identity, no persistent identity delta, and no remaining unfinished operation.
That inventory check does not claim that no transient sensor state changed.

The broker invokes `t2-touchid-failure.service` for any caught enrollment error.
That shared matching notification produces the misleading fingerprint rejection
toast. It is not independent evidence of a failed match or rejected capture.

## Apple implementation evidence

The locally available Catalina 19H15 BiometricKit framework, version
187.140.1, SHA-256
`de1ccb67d244dd90001235141bac4484df7697bc6f73e56ef61733b29dfdb991`,
contains the following x86-64 control flow. These are older host-framework
semantics, corroborated by the current T2's event stream; they are not a claim
to have inspected the same functions in the installed macOS build this turn.

| Handler | Recovered behavior |
| --- | --- |
| `BKEnrollTouchIDOperation statusMessage:client:` at `0x2b227` | Forwards to superclass at `0x2b55f`; capture-error mapping does not classify 63/64/90/91 as errors. |
| `BKEnrollOperation statusMessage:client:` at `0x2821a` | Progress 100..355 and status 70 send continue; 66..68 are failure paths; 63/64/90/91 forward at `0x28643`. |
| `BKOperation statusMessage:client:` at `0x27735` | Jump-table entries for 63 and 64 both reach presence notification at `0x277f9`. Status 64 additionally calls `changeState:2`. Neither terminates enrollment. |
| Presence callback block at `0x279d8` | Compares status against `0x3f` at `0x279f8`, passes the equality Boolean to `operation:presenceStateChanged:`. Thus 63 means presence true, 64 presence false. |
| Generic handler at `0x2789d` | Outside 51..80, only 99 has a state/termination action. 90 and 91 return through logging without an enrollment action. |

The live failure therefore agrees with a finger-presence notification. It does
not establish successful image capture, enrollment progress, or a new identity.
Earlier successful raw matching controls on this same T2 also emitted 63/64
with 36-byte status details and 90/91 without details.

## Linux overlay behavior

The project wrapper pins external commit
`826a86e55a9a745f50fb64672e5be32cf352cb76`, the protocol digest, and now the
broker digest. The external checkout is unchanged. The four allowed generic
statuses are precisely 63, 64, 90, and 91. They return the existing auxiliary
action without progress, identity, or a continue command. Presence-off leaves
the Linux operation active awaiting further events, encompassing Apple's
nonterminal waiting-state change without inventing another wire command.

The original reducer performs connection/operation checks, duplicate and
monotonic-sequence checks, version and status-detail validation, and
cancellation checks first. The wrapper handles only its exact final
`unknown enrollment status N` error for one of these four ordinals in an
otherwise active operation. It retains the checked sequence and fingerprint;
every other error still freezes the operation. Failure statuses 66/67/68 and
the distinct identity-result event retain their original behavior.

Enrollment notification calls now use terminal feedback. A failure says
enrollment did not complete and directs the user to the actual result. Shared
matching toasts/sounds are not invoked by this experimental enrollment runner.
The normal installed matching service is unaffected. Importing the pinned
broker under a non-main name permits this override before explicitly calling
its original main function and preserving its exit status.

Tests exercise a multi-event presence sequence followed by real progress and
identity result, all four statuses against malformed payloads, wrong versions,
unrelated operations/connections, duplicate/decreasing sequences, cancellation,
terminal failures, broker startup, and notification wording. Real enrollment
and persistence still require the next supervised hardware attempt.

Validation on Linux: all 11 overlay tests and all 122 research tests passed
(one expected macOS-only skip). The updated wrapper's hardware preflight
reported one host/live identity, verified local store, available capacity,
initialized retained sensor session, and `mutation_performed=false`.
