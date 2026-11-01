# Brizmo patch: hold child-channel writes during key re-exchange

> Branch `brizmo/ki-0.15.0` carries this patch (patch 1) unchanged plus patch 2, keyboard-interactive user
> authentication, described at the end of this file.

This branch (`brizmo/rekey-queue-0.15.0`) is upstream **swift-nio-ssh tag `0.15.0`**
(`3ec281496f28a3b6581afd946b759e2642f5cd8d`) plus one patch. It exists only until upstream
fixes the bug below; as soon as an official release contains a fix, consumers must switch
back to `https://github.com/apple/swift-nio-ssh.git` and this fork is retired.

- Upstream issue: https://github.com/apple/swift-nio-ssh/issues/250
- License: unchanged Apache License 2.0 (`LICENSE.txt`). Every modified or added file carries
  a "Modified/Added by the Brizmo project" line in its header.

## Bug (upstream 0.15.0, also present on `main` as of 2026-10-06)

When a key re-exchange is in progress — in particular when the **remote peer** initiates it, as
OpenSSH does on `RekeyLimit` — `SSHConnectionStateMachine` is in one of
`receivedKexInitWhenActive`, `sentKexInitWhenActive`, `rekeying` or
`rekeyingReceivedNewKeysState`. In those states `processOutboundMessage` throws
`protocolViolation` for every connection-protocol message (RFC 4253 §7.1: nothing but
transport/KEX messages until our own NEWKEYS is sent).

`NIOSSHHandler.writeFromChildChannel` passed child-channel messages straight to
`writeMessage` and only reported the error to the write promise. Most multiplexer writes carry
a `nil` promise (channel open/close, window adjust) and data promises are rarely inspected, so
the messages were **silently dropped**: lost channel data, lost window adjusts (the peer's send
window shrinks for good), and a channel opened during a re-key never completes. Observed in
practice as a stalled transfer after several server-initiated re-keys against OpenSSH with
`RekeyLimit 1M` (16 dropped 32 KiB packets per stall).

## Fix

`Sources/NIOSSH/NIOSSHHandler.swift`

- `writeFromChildChannel`: while `stateMachine.isKeyExchangeBlockingChannelMessages` is true, or
  while anything is already held, append `(message, promise)` to
  `childWritesHeldForKeyExchange` instead of writing it. Outside a re-key the queue is always
  empty, so the original code path runs unchanged.
- `releaseChildWritesHeldForKeyExchangeIfPossible`: writes held messages oldest-first for as long
  as the state machine accepts channel messages; each keeps its own promise, and a serialization
  error fails only that promise (same as a direct write). Re-entrancy-guarded. Flushes itself
  unless inside `channelRead` (where `channelReadComplete` flushes, as for every write there).
- Release points = every place the connection can leave the blocking states. Leaving happens only
  by writing our NEWKEYS, or by a disconnect (sent or received):
  - after each `processInboundMessageResult` in `channelRead` (server role emits NEWKEYS with
    the ECDH reply; also an inbound DISCONNECT -> `receivedDisconnect`);
  - after the `possibleFutureMessage` write (client role emits NEWKEYS after host key
    validation, which may complete outside any read);
  - after the DISCONNECT write in `_disconnect()` (`sentDisconnect`; the only outbound disconnect
    writer in this version).
  In a terminal (disconnected) state, "release" means every held write fails with exactly the
  error a direct write after disconnect gets (`protocolViolation`, "I/O after disconnect"), so
  nothing can dangle there either.
- `handlerRemoved`: every still-held promise is failed with `ChannelError.eof` (covers closing the
  connection, including an application closing it from `errorCaught`).
- `_childWritesHeldForKeyExchangeCount`: internal, test-only.

`Sources/NIOSSH/Connection State Machine/SSHConnectionStateMachine.swift`

- `isKeyExchangeBlockingChannelMessages`: exhaustive switch, true exactly for the four states
  above. `rekeyingSentNewKeysState` is excluded (channel messages are legal again there).

Not changed: KEX, user-auth and global request/response paths; the protocol semantics of
disconnect are unchanged (the only addition there is the held-write cleanup entry after the
DISCONNECT write in `_disconnect()` described above); no Foundation import; no logging.

**Scope: child-channel messages only.** This patch does NOT cover global requests: global-request
replies written during a re-key still hit the state machine's rejection (surfaced via
`fireErrorCaught`, not silently), and new global requests are only sent once the connection is
`.active` again — both exactly as upstream 0.15.0. It is not a general "all SSH messages during
re-key" fix.

## Tests

Status: patch candidate, pending verification (fork test run, review FINAL).

`Tests/NIOSSHTests/RekeyChildChannelWriteTests.swift` (deterministic, `EmbeddedChannel`, no
sleeps):

1. `testPeerInitiatedRekeyDoesNotDropClientChildWrites` — server-initiated re-key; client writes
   in `rekeying` and `rekeyingReceivedNewKeysState` (host key validation held); bytes arrive
   bit-exact and in order, promises succeed, release is flushed from the validation callback.
2. `testClientInitiatedRekeyDoesNotDropWritesOnEitherSide` — client writes in
   `sentKexInitWhenActive`, server writes in `rekeying`; server release inside `channelRead`.
3. `testCreateChannelDuringPeerInitiatedRekey` — CHANNEL_OPEN issued mid re-key completes.
4. `testHeldWindowAdjustRequestEOFAndCloseArriveInOrder` — 2 MiB window: a nil-promise window
   adjust generated mid re-key is held and delivered (server can then send past the window it
   would otherwise be stuck at); data+exec request, data+EOF, data+close on three channels all
   arrive in order and every promise succeeds.
5. `testWriteFromHeldWriteCompletionIsOrderedAfterHeldWrites` — a write issued from a released
   write's completion callback arrives after the held writes; all promises succeed.
6. `testHeldWritesFailWhenHandlerIsRemovedDuringRekey` — closing the connection mid re-key fails
   every held promise with `ChannelError.eof`.
7. `testHeldWritesFailWhenConnectionClosesOnErrorDuringRekey` — a corrupted packet mid re-key,
   application closes on error; held promises fail with `ChannelError.eof`.
8. `testHeldWritesConvergeOnLocalDisconnectDuringRekey` — `_disconnect()` mid re-key; held writes
   (plus one issued re-entrantly from a failure callback) fail in order with `protocolViolation`,
   same as a direct write after disconnect.
9. `testHeldWritesConvergeOnPeerDisconnectDuringRekey` — peer DISCONNECT mid re-key; held writes
   fail.

---

# Brizmo patch 2: keyboard-interactive user authentication (RFC 4256)

Branch `brizmo/ki-0.15.0` = `brizmo/rekey-queue-0.15.0` (`a089ae3f`, patch 1 above, unchanged) plus one commit.
There is no upstream issue for this: swift-nio-ssh has never implemented RFC 4256, and the only consumer we
know of that needs it is Sony's camera sshd (OpenSSH_7.9 on an a7 IV, firmware 4.00, which on 2026-10-31
offered **only** `keyboard-interactive`). Nothing outside Brizmo's Sony research tools uses this branch.

## Gap (upstream 0.15.0, also `main` as of 2026-11-01)

- `NIOSSHAvailableUserAuthenticationMethods(UserAuthFailureMessage)` silently dropped the method name
  `keyboard-interactive` in `default:`, so a keyboard-interactive-only server looked like it offered nothing.
- No `Offer`/`Request` case, no SSH_MSG_USERAUTH_INFO_REQUEST (60) / INFO_RESPONSE (61) on the wire, and the
  public `Offer` enum cannot be extended from outside the module.

## Change

Wire (`SSHMessages.swift`):
- `SSHMessage.userAuthInfoRequest` (60: name, instruction, language tag, `[Prompt(prompt, echo)]`) and
  `.userAuthInfoResponse` (61: responses) with read/write; `UserAuthRequestMessage.Method.keyboardInteractive
  (submethods:)` (string language tag written empty, string submethods comma-joined).
- Readers never trust `num-prompts`/`num-responses` for allocation: entries are read one by one and a short
  buffer yields `nil`.
- PK_OK read/write is untouched.

Message number 60 (`SSHPacketParser.swift`, `readSSHMessage(userAuthContext:)`):
- 60 is method-specific (RFC 4252 §6): PK_OK while publickey is in flight, INFO_REQUEST while
  keyboard-interactive is. The parser has an internal `userAuthMessageContext` (default = upstream behaviour,
  60 is PK_OK). The client's `UserAuthenticationState` sets it to `.keyboardInteractive` right after writing a
  keyboard-interactive USERAUTH_REQUEST and back to `.default` on USERAUTH_SUCCESS/FAILURE (and any non-KI
  request). Servers never switch it. 61 is always INFO_RESPONSE. Not public API.

Public API (`UserAuthenticationMethod.swift`, delegates, `NIOSSHError.swift`):
- `NIOSSHAvailableUserAuthenticationMethods.keyboardInteractive` (bit 3), parsed from and written to
  `"keyboard-interactive"`. **Not added to `.all`**: `.all` is what existing server delegates (e.g.
  `DenyAllServerAuthDelegate`) advertise in USERAUTH_FAILURE; adding it would change their wire output and
  five upstream tests that pin that list. Servers opt in by listing it.
- `Offer.keyboardInteractive(KeyboardInteractive(submethods:))`, `Request.keyboardInteractive(...)`.
- `NIOSSHKeyboardInteractiveChallenge` (name, instruction, languageTag, `[Prompt(text, echo)]`),
  `NIOSSHKeyboardInteractiveResponse` (responses), `NIOSSHKeyboardInteractiveServerStep`
  (`.challenge` / `.outcome`).
- Client delegate: `keyboardInteractiveChallengeReceived(_:responsePromise:)`; default implementation fails
  with the new `NIOSSHError.ErrorType.keyboardInteractiveChallengeUnhandled`.
- Client delegate: `nextAuthenticationType(availableMethods:serverOfferedMethodNames:nextChallengePromise:)`, which
  NIOSSH now calls; `serverOfferedMethodNames` is the server's USERAUTH_FAILURE list verbatim (unknown names such
  as `gssapi-with-mic` included; empty on the first call). Its default implementation calls the upstream
  requirement, so a server that lists only unknown methods is no longer indistinguishable from an empty list for
  delegates that care.
- Server delegate: `keyboardInteractiveRequestReceived(request:responsePromise:)` and
  `keyboardInteractiveResponseReceived(username:response:responsePromise:)`; default implementations answer
  `.outcome(.failure)`. Existing conformers compile unchanged.

State machine (`UserAuthenticationStateMachine.swift`), tracked next to the upstream `State` so that every
upstream transition is unchanged:
- Client: INFO_REQUEST is legal only while our in-flight request is keyboard-interactive and no earlier
  challenge is unanswered; otherwise `protocolViolation` (this includes publickey in flight: the client still
  does not handle PK_OK). The answer is checked against the prompt count (RFC 4256 §3.4) before anything is
  sent; a mismatch fails the connection (`protocolViolation`). Any number of rounds per attempt (a limit is
  the delegate's business). SUCCESS/FAILURE while our answer is still being produced is a `protocolViolation`
  (RFC 4256 §3.4: the server decides after the response); otherwise they are handled as before.
- Server: a keyboard-interactive request goes to the delegate only if `supportedAuthenticationMethods`
  contains it (else the usual FAILURE). A challenge answers the request like PK_OK does; INFO_RESPONSE is
  legal only while a challenge we sent is unanswered (`protocolViolation` otherwise), does not count toward
  `maxAuthAttempts`, and a response-count mismatch is answered with FAILURE (connection stays up). A new
  USERAUTH_REQUEST aborts the keyboard-interactive attempt in progress (RFC 4252 §5.1, which also says "A
  SSH_MSG_USERAUTH_FAILURE message MUST NOT be sent for an aborted method"). Every received request bumps a
  serial in a `KeyboardInteractiveClock` shared (via `NIOLockedValueBox`) with the futures of keyboard-interactive
  delegate callbacks; the clock also records which attempt still has a callback out. When the new request arrives,
  an unanswered challenge is forgotten and, if a callback is still out, the pending answer it accounts for is
  settled on the spot — nothing is sent for the aborted attempt. When that callback completes later, both its
  result (challenge, success, failure) and its error (`promise.fail`) find the serial stale and become
  `.abandoned`: no message, no error, nothing closed — whether the new request is still being authenticated or
  has already succeeded and the connection is active. A current callback's result and error behave as before.
  Non-keyboard-interactive pending answers are untouched (upstream pipelining semantics).
- The server path needs a reply type that can be an INFO_REQUEST. It is a separate internal enum
  (`NIOSSHUserAuthenticationServerStepMessage`) used through `receiveUserAuthRequestStep`; the upstream
  `receiveUserAuthRequest` keeps its signature (and behaviour for every other method) so existing exhaustive
  switches over `NIOSSHUserAuthenticationResponseMessage` are unchanged.

Connection state machine: `.userAuthentication` routes 60-as-INFO_REQUEST and 61 inbound and both messages
outbound; in every other state they take the existing "unexpected message" path. `NIOSSHHandler` is unchanged:
if a delegate answers after the channel was closed, the late message is written to a removed context and goes
nowhere (covered by tests, see below); NIOSSH never completes a delegate's promise itself. An aborted attempt's
late result never reaches the handler as a message at all (it is `nil`).

Not changed: KEX, transport protection, global requests, child channels, patch 1 (re-key write holding), PK_OK
handling, host-based auth. No Foundation import, no logging.

## Tests

`Tests/NIOSSHTests/KeyboardInteractiveAuthTests.swift`: wire round trips (0/1/3 prompts and responses,
partial reads, RFC byte layout, hostile counts), 60 disambiguation at buffer and packet-parser level, method
set parsing, client and server state machines (legal/illegal states, multi-round, count mismatch, attempt
counting, abandoned challenge), default implementations, and three end-to-end `BackToBackEmbeddedChannel`
cases (success + child channel data, wrong answer ending in an error with no dangling promise, two rounds).
Added after review STATIC-01: abandoned attempts (held delegate, A→B with late challenge／success／failure, both for
the initial challenge and for an INFO_RESPONSE), client outcome while its answer is held, held callback → channel
teardown → late answer (client challenge, server initial challenge, server response; nothing written, no error,
promise completed only by its owner), server method names verbatim (empty／unknown only／mixed), and parser context
restoration on a pair of connection state machines (after FAILURE, after SUCCESS, dropped on disconnect).
Changed after review STATIC-02: the abandoned-attempt tests now expect no message (`.abandoned`) and a settled
pending count; late `promise.fail` is covered; and over a pair of connection state machines (the client pipelines
B through the test-only `_abandonInFlightUserAuthRequestForTesting`), A held at the initial challenge or at the
INFO_RESPONSE, B succeeds (connection active, channel traffic still forwarded) or fails (only B's FAILURE goes
out), then A answers late in four ways: nothing is written, no error. Names verbatim also for `partialSuccess`.
Test fixtures (STATIC-03): every promise a test delegate holds is recorded in a ledger; `tearDown` fails the ones a
test left open (an assertion failed or a `try` threw first, e.g. under a mutation) and reports them, so a failing test
ends as an XCTest failure instead of a "leaking promise" crash. Completed promises are never completed again.
Interop against real OpenSSH (client and sshd) lives in Brizmo's `ssh_spike/Tools/ki_interop.sh`.

Status: patch candidate, pending verification (fork test run, interop, review FINAL).
