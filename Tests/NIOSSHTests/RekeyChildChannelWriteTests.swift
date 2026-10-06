//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// Added by the Brizmo project (2026-10-07): regression tests for child-channel writes issued
// during a key re-exchange. See BRIZMO-PATCH.md and
// https://github.com/apple/swift-nio-ssh/issues/250.
//
//===----------------------------------------------------------------------===//

import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSH

/// Records, in order, every byte a child channel reads plus the channel-level events it sees:
/// `"data"` (consecutive reads collapse into one entry), `"exec:<command>"`, `"eof"` and `"inactive"`.
private final class ChildEventRecorder: ChannelInboundHandler {
    typealias InboundIn = SSHChannelData

    private(set) var bytes: [UInt8] = []
    private(set) var events: [String] = []

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = self.unwrapInboundIn(data)
        guard case .byteBuffer(let buffer) = message.data else {
            XCTFail("Unexpected non-ByteBuffer channel data")
            return
        }
        self.bytes.append(contentsOf: buffer.readableBytesView)
        if self.events.last != "data" {
            self.events.append("data")
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if let exec = event as? SSHChannelRequestEvent.ExecRequest {
            self.events.append("exec:\(exec.command)")
        } else if let channelEvent = event as? ChannelEvent, channelEvent == .inputClosed {
            self.events.append("eof")
        }
        context.fireUserInboundEventTriggered(event)
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.events.append("inactive")
        context.fireChannelInactive()
    }
}

/// Records errors reaching the end of the parent pipeline and closes the connection, like a typical
/// application error handler.
private final class CloseOnErrorHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    private(set) var errors: [Error] = []

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.errors.append(error)
        context.close(promise: nil)
    }
}

/// Accepts every host key, but can hold one validation open so the client stays in the
/// "peer NEWKEYS received, ours not yet sent" re-key state for as long as the test wants.
private final class GatedHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate {
    var holdNextValidation = false
    private var heldValidation: EventLoopPromise<Void>?

    var isHoldingValidation: Bool {
        self.heldValidation != nil
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        if self.holdNextValidation {
            self.holdNextValidation = false
            self.heldValidation = validationCompletePromise
        } else {
            validationCompletePromise.succeed(())
        }
    }

    func releaseHeldValidation() {
        let promise = self.heldValidation
        self.heldValidation = nil
        promise?.succeed(())
    }
}

/// Regression tests for apple/swift-nio-ssh#250: before the patch, any child-channel message written while a key
/// re-exchange was in flight was rejected by the connection state machine and silently dropped.
///
/// Every step is driven by hand on `EmbeddedChannel`s (no sleeps, no real time), so the re-key states are reached
/// deterministically:
///   - `rekeying` / `rekeyingReceivedNewKeysState` on the client (server-initiated re-key, held host key validation),
///   - `sentKexInitWhenActive` on the client and `rekeying` on the server (client-initiated re-key).
final class RekeyChildChannelWriteTests: XCTestCase {
    private typealias Outcome = NIOLoopBoundBox<Result<Void, Error>?>

    private var channel: BackToBackEmbeddedChannel!
    /// Server-side child channels and their recorders, in the order the client opened them.
    private var serverChildren: [Channel] = []
    private var serverRecorders: [ChildEventRecorder] = []

    override func setUp() {
        self.channel = BackToBackEmbeddedChannel()
        self.serverChildren = []
        self.serverRecorders = []
    }

    override func tearDown() {
        try? self.channel.finish()
        self.channel = nil
        self.serverChildren = []
        self.serverRecorders = []
    }

    // MARK: Helpers

    /// Same wiring as `BackToBackEmbeddedChannel.configureWithHarness`, except that every server-side child channel
    /// gets its own `ChildEventRecorder` and is remembered in `serverChildren`.
    private func configure(
        clientServerAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        clientMaximumPacketSize: Int? = nil
    ) throws {
        let harness = TestHarness()
        var clientConfiguration = SSHClientConfiguration(
            userAuthDelegate: harness.clientAuthDelegate,
            serverAuthDelegate: clientServerAuthDelegate,
            globalRequestDelegate: harness.clientGlobalRequestDelegate
        )
        if let size = clientMaximumPacketSize {
            clientConfiguration.maximumPacketSize = size
        }
        let clientHandler = NIOSSHHandler(
            role: .client(clientConfiguration),
            allocator: self.channel.client.allocator,
            inboundChildChannelInitializer: nil
        )
        let serverHandler = NIOSSHHandler(
            role: .server(
                .init(
                    hostKeys: harness.serverHostKeys,
                    userAuthDelegate: harness.serverAuthDelegate,
                    globalRequestDelegate: harness.serverGlobalRequestDelegate,
                    banner: harness.serverAuthBanner
                )
            ),
            allocator: self.channel.server.allocator
        ) { channel, _ in
            let recorder = ChildEventRecorder()
            self.serverChildren.append(channel)
            self.serverRecorders.append(recorder)
            return channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandler(recorder)
            }
        }

        try self.channel.client.pipeline.syncOperations.addHandler(clientHandler)
        try self.channel.server.pipeline.syncOperations.addHandler(serverHandler)
    }

    /// Opens one client-initiated child channel on an already active connection.
    private func openClientChild(recorder: ChildEventRecorder) throws -> Channel {
        let before = self.serverChildren.count
        var clientChild: Channel?
        self.channel.clientSSHHandler?.createChannel(nil, channelType: .session) { channel, _ in
            clientChild = channel
            return channel.eventLoop.makeCompletedFuture {
                try channel.pipeline.syncOperations.addHandler(recorder)
            }
        }
        try self.channel.interactInMemory()

        XCTAssertEqual(self.serverChildren.count, before + 1)
        return try XCTUnwrap(clientChild)
    }

    /// Brings the connection up and opens one client-initiated child channel.
    private func connectAndOpenChild(
        clientServerAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        clientRecorder: ChildEventRecorder
    ) throws -> Channel {
        try self.configure(clientServerAuthDelegate: clientServerAuthDelegate)
        try self.channel.activate()
        try self.channel.interactInMemory()
        return try self.openClientChild(recorder: clientRecorder)
    }

    /// Bytes read so far by the server side of the `index`-th child channel (empty if it does not exist).
    private func serverBytes(_ index: Int = 0) -> [UInt8] {
        index < self.serverRecorders.count ? self.serverRecorders[index].bytes : []
    }

    private func serverEvents(_ index: Int) -> [String] {
        index < self.serverRecorders.count ? self.serverRecorders[index].events : []
    }

    /// Moves every write currently flushed on `from` into `to`'s inbound side, one write at a time, without
    /// running the other direction. Returns how many writes were moved.
    @discardableResult
    private func deliverAll(from: EmbeddedChannel, to: EmbeddedChannel) throws -> Int {
        var count = 0
        while let datum = try from.readOutbound(as: IOData.self) {
            try to.writeInbound(datum)
            count += 1
        }
        return count
    }

    private func discardOutbound(_ channel: EmbeddedChannel) throws {
        while try channel.readOutbound(as: IOData.self) != nil {}
    }

    /// Deterministic, chunk-specific content so that loss, duplication and reordering are all visible.
    private func payload(seed: UInt8, count: Int) -> [UInt8] {
        var state = UInt32(seed) &* 2_654_435_761 &+ 1
        return (0..<count).map { _ in
            state = state &* 1_664_525 &+ 1_013_904_223
            return UInt8(truncatingIfNeeded: state >> 24)
        }
    }

    private func channelData(_ bytes: [UInt8], allocator: ByteBufferAllocator) -> SSHChannelData {
        var buffer = allocator.buffer(capacity: bytes.count)
        buffer.writeBytes(bytes)
        return SSHChannelData(type: .channel, data: .byteBuffer(buffer))
    }

    /// Records how `future` ends; if `order` is given, appends `label` to it on completion.
    /// Register this before any other callback on the same future when completion order matters.
    private func track(
        _ future: EventLoopFuture<Void>,
        label: String = "",
        order: NIOLoopBoundBox<[String]>? = nil
    ) -> Outcome {
        let outcome = Outcome(nil, eventLoop: future.eventLoop)
        future.whenComplete { result in
            outcome.value = result
            order?.value.append(label)
        }
        return outcome
    }

    /// Writes `bytes` on `child` and records how the write promise ends.
    private func write(
        _ bytes: [UInt8],
        on child: Channel,
        label: String = "",
        order: NIOLoopBoundBox<[String]>? = nil
    ) -> Outcome {
        self.track(
            child.writeAndFlush(self.channelData(bytes, allocator: child.allocator)),
            label: label,
            order: order
        )
    }

    private func isPending(_ outcome: Outcome) -> Bool {
        outcome.value == nil
    }

    private func succeeded(_ outcome: Outcome) -> Bool {
        if case .some(.success) = outcome.value { return true }
        return false
    }

    private func failure(_ outcome: Outcome) -> Error? {
        if case .some(.failure(let error)) = outcome.value { return error }
        return nil
    }

    private func isProtocolViolation(_ error: Error?) -> Bool {
        (error as? NIOSSHError)?.type == .protocolViolation
    }

    // MARK: Data during peer- and self-initiated re-keys

    /// The remote peer (server) starts a re-key; the client keeps writing child-channel data through `rekeying` and
    /// `rekeyingReceivedNewKeysState`. Every byte must reach the peer, in order, and every write promise must succeed —
    /// and the held writes must be flushed by the client's own NEWKEYS write alone (the host-key-validation path).
    func testPeerInitiatedRekeyDoesNotDropClientChildWrites() throws {
        let gate = GatedHostKeyDelegate()
        let child = try self.connectAndOpenChild(clientServerAuthDelegate: gate, clientRecorder: ChildEventRecorder())
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)

        // Baseline outside any re-key: unchanged upstream path.
        let before = self.payload(seed: 1, count: 1500)
        let beforeWrite = self.write(before, on: child)
        try self.channel.interactInMemory()
        XCTAssertTrue(self.succeeded(beforeWrite))
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)
        XCTAssertEqual(self.serverBytes(), before)

        // Server starts the re-key; hold the client's host key validation for this round.
        gate.holdNextValidation = true
        try XCTUnwrap(self.channel.serverSSHHandler)._rekey()

        // Server KEXINIT -> client. The client answers with KEXINIT + ECDH init and is now `rekeying`.
        XCTAssertEqual(try self.deliverAll(from: self.channel.server, to: self.channel.client), 1)

        let duringRekeying = self.payload(seed: 2, count: 3000)
        let duringRekeyingWrite = self.write(duringRekeying, on: child)
        XCTAssertTrue(self.isPending(duringRekeyingWrite), "write must be held, not failed or sent, while rekeying")
        XCTAssertGreaterThan(clientHandler._childWritesHeldForKeyExchangeCount, 0)

        // Client KEXINIT + ECDH init -> server. Server replies with ECDH reply + NEWKEYS.
        XCTAssertGreaterThan(try self.deliverAll(from: self.channel.client, to: self.channel.server), 0)
        XCTAssertGreaterThan(try self.deliverAll(from: self.channel.server, to: self.channel.client), 0)

        // The client has the peer's NEWKEYS but cannot send its own until host key validation completes:
        // it is in `rekeyingReceivedNewKeysState`.
        XCTAssertTrue(gate.isHoldingValidation)
        let duringReceivedNewKeys = self.payload(seed: 3, count: 2500)
        let duringReceivedNewKeysWrite = self.write(duringReceivedNewKeys, on: child)
        XCTAssertTrue(self.isPending(duringRekeyingWrite))
        XCTAssertTrue(self.isPending(duringReceivedNewKeysWrite))
        XCTAssertGreaterThanOrEqual(clientHandler._childWritesHeldForKeyExchangeCount, 2)

        // Completing validation sends our NEWKEYS from the future callback; the held writes must be released and
        // flushed right there (EmbeddedChannel only succeeds write promises on flush).
        gate.releaseHeldValidation()
        self.channel.run()
        XCTAssertTrue(self.succeeded(duringRekeyingWrite))
        XCTAssertTrue(self.succeeded(duringReceivedNewKeysWrite))
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)

        try self.channel.interactInMemory()
        XCTAssertEqual(self.serverBytes(), before + duringRekeying + duringReceivedNewKeys)

        // And the connection is still healthy afterwards.
        let after = self.payload(seed: 4, count: 1200)
        let afterWrite = self.write(after, on: child)
        try self.channel.interactInMemory()
        XCTAssertTrue(self.succeeded(afterWrite))
        XCTAssertEqual(self.serverBytes(), before + duringRekeying + duringReceivedNewKeys + after)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)
    }

    /// The client starts a re-key, so for the server the re-key is peer-initiated. The client writes while in
    /// `sentKexInitWhenActive`, the server writes while `rekeying`. The server's held write must be released by the
    /// NEWKEYS it emits inside `channelRead` and flushed by `channelReadComplete`.
    func testClientInitiatedRekeyDoesNotDropWritesOnEitherSide() throws {
        let clientRecorder = ChildEventRecorder()
        let child = try self.connectAndOpenChild(
            clientServerAuthDelegate: AcceptAllHostKeysDelegate(),
            clientRecorder: clientRecorder
        )
        let serverChild = try XCTUnwrap(self.serverChildren.first)
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)
        let serverHandler = try XCTUnwrap(self.channel.serverSSHHandler)

        try clientHandler._rekey()

        // Client is in `sentKexInitWhenActive`.
        let clientData = self.payload(seed: 10, count: 2800)
        let clientWrite = self.write(clientData, on: child)
        XCTAssertTrue(self.isPending(clientWrite))
        XCTAssertGreaterThan(clientHandler._childWritesHeldForKeyExchangeCount, 0)

        // Client KEXINIT -> server: the server answers with its KEXINIT and is now `rekeying`.
        XCTAssertEqual(try self.deliverAll(from: self.channel.client, to: self.channel.server), 1)
        let serverData = self.payload(seed: 11, count: 2200)
        let serverWrite = self.write(serverData, on: serverChild)
        XCTAssertTrue(self.isPending(serverWrite))
        XCTAssertGreaterThan(serverHandler._childWritesHeldForKeyExchangeCount, 0)

        // Server KEXINIT -> client: the client sends its ECDH init and is `rekeying`; still nothing released.
        XCTAssertGreaterThan(try self.deliverAll(from: self.channel.server, to: self.channel.client), 0)
        XCTAssertTrue(self.isPending(clientWrite))

        // Client ECDH init -> server: the server emits ECDH reply + NEWKEYS from inside channelRead.
        XCTAssertGreaterThan(try self.deliverAll(from: self.channel.client, to: self.channel.server), 0)
        XCTAssertTrue(self.succeeded(serverWrite), "server write must be released after its NEWKEYS and flushed")
        XCTAssertEqual(serverHandler._childWritesHeldForKeyExchangeCount, 0)

        // Let everything settle (client NEWKEYS via the immediate host key validation, both NEWKEYS received).
        try self.channel.interactInMemory()
        XCTAssertTrue(self.succeeded(clientWrite))
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)
        XCTAssertEqual(self.serverBytes(), clientData)
        XCTAssertEqual(clientRecorder.bytes, serverData)

        // Both directions keep working after the re-key.
        let clientAfter = self.payload(seed: 12, count: 900)
        let serverAfter = self.payload(seed: 13, count: 700)
        let clientAfterWrite = self.write(clientAfter, on: child)
        let serverAfterWrite = self.write(serverAfter, on: serverChild)
        try self.channel.interactInMemory()
        XCTAssertTrue(self.succeeded(clientAfterWrite))
        XCTAssertTrue(self.succeeded(serverAfterWrite))
        XCTAssertEqual(self.serverBytes(), clientData + clientAfter)
        XCTAssertEqual(clientRecorder.bytes, serverData + serverAfter)
    }

    /// Opening a child channel while a peer-initiated re-key is in flight goes through the same multiplexer write
    /// path (CHANNEL_OPEN). It must be held and sent after the re-key instead of being dropped (which left the
    /// channel promise hanging forever).
    func testCreateChannelDuringPeerInitiatedRekey() throws {
        try self.configure(clientServerAuthDelegate: AcceptAllHostKeysDelegate())
        try self.channel.activate()
        try self.channel.interactInMemory()
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)

        try XCTUnwrap(self.channel.serverSSHHandler)._rekey()
        XCTAssertEqual(try self.deliverAll(from: self.channel.server, to: self.channel.client), 1)

        // Client is `rekeying`.
        let opened = NIOLoopBoundBox<Result<Channel, Error>?>(nil, eventLoop: self.channel.client.eventLoop)
        let promise = self.channel.client.eventLoop.makePromise(of: Channel.self)
        promise.futureResult.whenComplete { result in opened.value = result }
        clientHandler.createChannel(promise, channelType: .session) { channel, _ in
            channel.eventLoop.makeSucceededFuture(())
        }
        XCTAssertNil(opened.value)
        XCTAssertGreaterThan(clientHandler._childWritesHeldForKeyExchangeCount, 0)

        try self.channel.interactInMemory()

        guard case .some(.success(let child)) = opened.value else {
            XCTFail("channel open must complete after the re-key, got \(String(describing: opened.value))")
            return
        }
        XCTAssertEqual(self.serverChildren.count, 1)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)

        let data = self.payload(seed: 20, count: 1000)
        let dataWrite = self.write(data, on: child)
        try self.channel.interactInMemory()
        XCTAssertTrue(self.succeeded(dataWrite))
        XCTAssertEqual(self.serverBytes(), data)
    }

    // MARK: Control messages and re-entrancy

    /// Control messages are held exactly like data. With a 2 MiB receive window (32 KiB max packet × 64), the client
    /// reads 1.2 MB from the server while in `sentKexInitWhenActive`; crossing half the window makes the client child
    /// emit a window adjust with a `nil` promise, which must be held (upstream dropped it, permanently shrinking the
    /// server's send window). Alongside, the client issues data + exec request on channel A, data + EOF on channel B
    /// and data + close on channel C. After the re-key everything must arrive in order, every promise must succeed,
    /// and the server's send window must already include the held adjust before anything else can top it up.
    func testHeldWindowAdjustRequestEOFAndCloseArriveInOrder() throws {
        try self.configure(clientServerAuthDelegate: AcceptAllHostKeysDelegate(), clientMaximumPacketSize: 32768)
        try self.channel.activate()
        try self.channel.interactInMemory()

        let clientA = ChildEventRecorder()
        let childA = try self.openClientChild(recorder: clientA)
        let childB = try self.openClientChild(recorder: ChildEventRecorder())
        let childC = try self.openClientChild(recorder: ChildEventRecorder())
        XCTAssertEqual(self.serverChildren.count, 3)
        let serverChildA = try XCTUnwrap(self.serverChildren.first)
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)

        // Client starts a re-key: `sentKexInitWhenActive`. Its KEXINIT stays in the client's outbound buffer for now,
        // so the server is still active and keeps sending.
        try clientHandler._rekey()

        // 1_200_000 bytes in 32 KiB packets. The window manager tops up when the available window is <= half
        // (1_048_576): that happens exactly after the 32nd packet (32 × 32_768 = 1_048_576 consumed), so the client
        // child emits exactly one window adjust of +1_048_576 while reading. The remaining 151_424 bytes leave the
        // client's view of the available window at 1_945_728 (> half), so no further adjust is emitted here.
        let firstDownload = self.payload(seed: 40, count: 1_200_000)
        let firstDownloadWrite = self.write(firstDownload, on: serverChildA)
        XCTAssertGreaterThan(try self.deliverAll(from: self.channel.server, to: self.channel.client), 0)
        XCTAssertEqual(clientA.bytes, firstDownload)
        XCTAssertEqual(
            clientHandler._childWritesHeldForKeyExchangeCount,
            1,
            "the nil-promise window adjust must be held, not dropped"
        )

        // Data + request on A, data + EOF on B, data + close on C — all while still in `sentKexInitWhenActive`.
        let dataA = self.payload(seed: 41, count: 1000)
        let dataB = self.payload(seed: 42, count: 1100)
        let dataC = self.payload(seed: 43, count: 1200)
        let dataAWrite = self.write(dataA, on: childA)
        let execA = self.track(
            childA.triggerUserOutboundEvent(SSHChannelRequestEvent.ExecRequest(command: "brizmo", wantReply: false))
        )
        let dataBWrite = self.write(dataB, on: childB)
        let eofB = self.track(childB.close(mode: .output))
        let dataCWrite = self.write(dataC, on: childC)
        let closeC = self.track(childC.close())

        for outcome in [dataAWrite, execA, dataBWrite, eofB, dataCWrite, closeC] {
            XCTAssertTrue(self.isPending(outcome))
        }
        XCTAssertGreaterThanOrEqual(clientHandler._childWritesHeldForKeyExchangeCount, 7)

        // Finish the re-key (and the B/C close handshakes).
        try self.channel.interactInMemory()
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)
        XCTAssertTrue(self.succeeded(firstDownloadWrite))
        for outcome in [dataAWrite, execA, dataBWrite, eofB, dataCWrite, closeC] {
            XCTAssertTrue(self.succeeded(outcome))
        }

        // Per-channel arrival and order on the server.
        XCTAssertEqual(self.serverBytes(0), dataA)
        XCTAssertEqual(self.serverEvents(0), ["data", "exec:brizmo"])
        XCTAssertEqual(self.serverBytes(1), dataB)
        XCTAssertEqual(self.serverEvents(1), ["data", "inactive"])  // EOF without half-closure => full close.
        XCTAssertEqual(self.serverBytes(2), dataC)
        XCTAssertEqual(self.serverEvents(2), ["data", "inactive"])

        // The server's send window on A is now 2_097_152 - 1_200_000 + 1_048_576 = 1_945_728 *only if the held adjust
        // was delivered*; without it, it is 897_152. Check this before any further interaction: once the client
        // reads more data it would emit a fresh adjust and could mask a lost one. 1_500_000 bytes fit only in the
        // former, and the write promise (carried by the last packet) completes on flush only if every packet was
        // handed to the parent channel — so it must already have succeeded right here.
        let secondDownload = self.payload(seed: 44, count: 1_500_000)
        let secondDownloadWrite = self.write(secondDownload, on: serverChildA)
        XCTAssertTrue(
            self.succeeded(secondDownloadWrite),
            "the held window adjust must have reached the server: 1.5 MB must fit its send window without another top-up"
        )
        try self.channel.interactInMemory()
        XCTAssertTrue(self.succeeded(secondDownloadWrite))
        XCTAssertEqual(clientA.bytes.count, firstDownload.count + secondDownload.count)
        XCTAssertEqual(clientA.bytes, firstDownload + secondDownload)
    }

    /// A completion callback of a released write writes again on the same child. The earlier held writes must reach
    /// the peer first, the new write after them, and every promise must complete successfully.
    func testWriteFromHeldWriteCompletionIsOrderedAfterHeldWrites() throws {
        let gate = GatedHostKeyDelegate()
        let child = try self.connectAndOpenChild(clientServerAuthDelegate: gate, clientRecorder: ChildEventRecorder())
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)

        gate.holdNextValidation = true
        try XCTUnwrap(self.channel.serverSSHHandler)._rekey()
        try self.deliverAll(from: self.channel.server, to: self.channel.client)

        let order = NIOLoopBoundBox<[String]>([], eventLoop: child.eventLoop)
        let first = self.payload(seed: 50, count: 1000)
        let second = self.payload(seed: 51, count: 1000)
        let third = self.payload(seed: 52, count: 1000)
        let thirdData = self.channelData(third, allocator: child.allocator)
        let thirdOutcome = Outcome(nil, eventLoop: child.eventLoop)

        let firstFuture = child.writeAndFlush(self.channelData(first, allocator: child.allocator))
        let firstOutcome = self.track(firstFuture, label: "first", order: order)
        firstFuture.whenComplete { _ in
            // Runs while the held writes are being released.
            child.writeAndFlush(thirdData).whenComplete { result in
                thirdOutcome.value = result
                order.value.append("third")
            }
        }
        let secondOutcome = self.write(second, on: child, label: "second", order: order)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 2)

        // Drive the re-key to the point where the client's NEWKEYS is only waiting for host key validation.
        try self.deliverAll(from: self.channel.client, to: self.channel.server)
        try self.deliverAll(from: self.channel.server, to: self.channel.client)
        XCTAssertTrue(gate.isHoldingValidation)
        XCTAssertTrue(self.isPending(firstOutcome))
        XCTAssertTrue(self.isPending(secondOutcome))

        gate.releaseHeldValidation()
        self.channel.run()
        try self.channel.interactInMemory()

        XCTAssertTrue(self.succeeded(firstOutcome))
        XCTAssertTrue(self.succeeded(secondOutcome))
        XCTAssertTrue(self.succeeded(thirdOutcome))
        XCTAssertEqual(order.value, ["first", "second", "third"])
        XCTAssertEqual(self.serverBytes(), first + second + third)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)
    }

    // MARK: Lifecycle: every held promise converges

    /// Closing the connection while writes are held for a re-key must fail every held promise
    /// (with `ChannelError.eof`, from `handlerRemoved`) instead of leaving it dangling.
    func testHeldWritesFailWhenHandlerIsRemovedDuringRekey() throws {
        let child = try self.connectAndOpenChild(
            clientServerAuthDelegate: AcceptAllHostKeysDelegate(),
            clientRecorder: ChildEventRecorder()
        )
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)

        try XCTUnwrap(self.channel.serverSSHHandler)._rekey()
        XCTAssertEqual(try self.deliverAll(from: self.channel.server, to: self.channel.client), 1)
        // The client's KEXINIT + ECDH init never reaches the server: the client stays `rekeying` until it closes.
        try self.discardOutbound(self.channel.client)

        let first = self.write(self.payload(seed: 30, count: 1000), on: child)
        let second = self.write(self.payload(seed: 31, count: 1000), on: child)
        XCTAssertTrue(self.isPending(first))
        XCTAssertTrue(self.isPending(second))
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 2)

        // Closing the parent channel tears the pipeline down, which removes the SSH handler.
        self.channel.client.close(promise: nil)
        self.channel.run()

        XCTAssertEqual(self.failure(first) as? ChannelError, .eof)
        XCTAssertEqual(self.failure(second) as? ChannelError, .eof)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)
        XCTAssertEqual(self.serverBytes(), [])

        try self.discardOutbound(self.channel.client)
        try self.discardOutbound(self.channel.server)
    }

    /// An inbound protocol error during a re-key (here: a corrupted packet failing authentication) makes the
    /// application close the connection. Every held promise must fail rather than dangle.
    func testHeldWritesFailWhenConnectionClosesOnErrorDuringRekey() throws {
        let child = try self.connectAndOpenChild(
            clientServerAuthDelegate: AcceptAllHostKeysDelegate(),
            clientRecorder: ChildEventRecorder()
        )
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)
        let closer = CloseOnErrorHandler()
        try self.channel.client.pipeline.syncOperations.addHandler(closer)

        // Client is `sentKexInitWhenActive`; its KEXINIT is never delivered.
        try clientHandler._rekey()
        try self.discardOutbound(self.channel.client)

        let first = self.write(self.payload(seed: 60, count: 1000), on: child)
        let second = self.write(self.payload(seed: 61, count: 1000), on: child)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 2)

        // A real server packet with its last byte (part of the authentication tag) flipped.
        try XCTUnwrap(self.channel.serverSSHHandler)._rekey()
        let datum = try XCTUnwrap(try self.channel.server.readOutbound(as: IOData.self))
        guard case .byteBuffer(var corrupted) = datum else {
            XCTFail("unexpected outbound type")
            return
        }
        let lastIndex = corrupted.writerIndex - 1
        let lastByte = try XCTUnwrap(corrupted.getInteger(at: lastIndex, as: UInt8.self))
        corrupted.setInteger(lastByte ^ 0xFF, at: lastIndex)
        try self.channel.client.writeInbound(IOData.byteBuffer(corrupted))
        self.channel.run()

        XCTAssertFalse(closer.errors.isEmpty, "the corrupted packet must surface as an error")
        XCTAssertFalse(self.channel.client.isActive)
        XCTAssertEqual(self.failure(first) as? ChannelError, .eof)
        XCTAssertEqual(self.failure(second) as? ChannelError, .eof)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)

        try self.discardOutbound(self.channel.client)
        try self.discardOutbound(self.channel.server)
    }

    /// A local disconnect during a re-key moves the state machine to `sentDisconnect`, from which nothing can be sent
    /// any more. Held writes must fail at once with the same error a direct write after disconnect gets — including a
    /// write issued from a held write's failure callback while the queue is still being drained (re-entrancy).
    func testHeldWritesConvergeOnLocalDisconnectDuringRekey() throws {
        let child = try self.connectAndOpenChild(
            clientServerAuthDelegate: AcceptAllHostKeysDelegate(),
            clientRecorder: ChildEventRecorder()
        )
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)

        try XCTUnwrap(self.channel.serverSSHHandler)._rekey()
        XCTAssertEqual(try self.deliverAll(from: self.channel.server, to: self.channel.client), 1)
        try self.discardOutbound(self.channel.client)

        let order = NIOLoopBoundBox<[String]>([], eventLoop: child.eventLoop)
        let firstData = self.channelData(self.payload(seed: 70, count: 1000), allocator: child.allocator)
        let thirdData = self.channelData(self.payload(seed: 72, count: 1000), allocator: child.allocator)
        let thirdOutcome = Outcome(nil, eventLoop: child.eventLoop)

        let firstFuture = child.writeAndFlush(firstData)
        let firstOutcome = self.track(firstFuture, label: "first", order: order)
        firstFuture.whenComplete { _ in
            // Issued while "second" is still held.
            child.writeAndFlush(thirdData).whenComplete { result in
                thirdOutcome.value = result
                order.value.append("third")
            }
        }
        let secondOutcome = self.write(self.payload(seed: 71, count: 1000), on: child, label: "second", order: order)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 2)

        try clientHandler._disconnect()
        self.channel.run()

        XCTAssertTrue(self.isProtocolViolation(self.failure(firstOutcome)))
        XCTAssertTrue(self.isProtocolViolation(self.failure(secondOutcome)))
        XCTAssertTrue(self.isProtocolViolation(self.failure(thirdOutcome)))
        XCTAssertEqual(order.value, ["first", "second", "third"])
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)

        // Same error as a direct (never held) write after disconnect.
        let direct = self.write(self.payload(seed: 73, count: 100), on: child)
        XCTAssertTrue(self.isProtocolViolation(self.failure(direct)))

        try self.discardOutbound(self.channel.client)
        try self.discardOutbound(self.channel.server)
    }

    /// The peer disconnects during a re-key. Every held promise must fail (they can never be sent).
    func testHeldWritesConvergeOnPeerDisconnectDuringRekey() throws {
        let child = try self.connectAndOpenChild(
            clientServerAuthDelegate: AcceptAllHostKeysDelegate(),
            clientRecorder: ChildEventRecorder()
        )
        let clientHandler = try XCTUnwrap(self.channel.clientSSHHandler)
        let serverHandler = try XCTUnwrap(self.channel.serverSSHHandler)

        try serverHandler._rekey()
        XCTAssertEqual(try self.deliverAll(from: self.channel.server, to: self.channel.client), 1)
        try self.discardOutbound(self.channel.client)

        let first = self.write(self.payload(seed: 80, count: 1000), on: child)
        let second = self.write(self.payload(seed: 81, count: 1000), on: child)
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 2)

        try serverHandler._disconnect()
        try self.deliverAll(from: self.channel.server, to: self.channel.client)
        self.channel.run()

        XCTAssertNotNil(self.failure(first))
        XCTAssertNotNil(self.failure(second))
        XCTAssertEqual(clientHandler._childWritesHeldForKeyExchangeCount, 0)
        XCTAssertEqual(self.serverBytes(), [])

        try self.discardOutbound(self.channel.client)
        try self.discardOutbound(self.channel.server)
    }
}
