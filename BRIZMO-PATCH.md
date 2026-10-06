# Brizmo patch: hold child-channel writes during key re-exchange

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
