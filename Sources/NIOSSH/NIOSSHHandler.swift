//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
// Modified by the Brizmo project (2026-10-07): child-channel writes issued during a key
// re-exchange are held and released in order instead of being dropped. See BRIZMO-PATCH.md
// and https://github.com/apple/swift-nio-ssh/issues/250.
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A `ChannelDuplexHandler` that implements the SSH protocol.
///
/// SSH is a protocol originally designed to negotiate a secure transportation channel over
/// which a login shell can be run. This allows users to remotely log in to machines and
/// administrate them over the network securely.
///
/// However, in addition to the ability to open a remote shell, SSH supports a number of
/// other usage models, including port forwarding. It is also able to construct somewhat
/// arbitrary secure multiplexed channels.
public final class NIOSSHHandler {
    internal var channel: Channel? {
        self.context.map { $0.channel }
    }

    /// The state machine that drives the connection.
    private var stateMachine: SSHConnectionStateMachine

    /// A buffer used to provide scratch space for writing data to the network.
    ///
    /// This is an IUO because it should never be nil, but it is only initialized once the
    /// handler is added to a channel.
    private var outboundFrameBuffer: ByteBuffer

    /// Whether there's a pending unflushed write.
    private var pendingWrite: Bool

    private var context: ChannelHandlerContext?

    // Must be optional as we need to pass it a reference to self.
    private var multiplexer: SSHChannelMultiplexer?

    // Whether we're expecting a channelReadComplete.
    private var expectingChannelReadComplete: Bool = false

    // A buffer of pending channel initializations. A channel initialization is pending if
    // we're attempting to initialize a channel before user auth is complete.
    private var pendingChannelInitializations:
        CircularBuffer<
            (
                promise: EventLoopPromise<Channel>?, channelType: SSHChannelType,
                initializer: SSHChildChannel.Initializer?
            )
        >

    // A buffer of pending global requests. A global request is pending if we tried to send it before user auth completed.
    private var pendingGlobalRequests: CircularBuffer<(SSHMessage.GlobalRequestMessage, PendingGlobalRequestResponse?)>

    private var pendingGlobalRequestResponses: CircularBuffer<PendingGlobalRequestResponse?>

    // BRIZMO PATCH (apple/swift-nio-ssh#250): child-channel messages held back while a key re-exchange is in flight.
    //
    // Once the remote peer (or we) start a re-key, the connection state machine refuses to serialize any
    // connection-protocol message until our own NEWKEYS has been sent (RFC 4253 §7.1). Child channels
    // know nothing about that: upstream handed their writes straight to `writeMessage`, the state machine threw,
    // and the error was only reported to the write promise — which is `nil` for most multiplexer writes
    // (window adjusts, channel open/close) and is routinely ignored for data. The bytes were silently lost.
    //
    // Instead we hold every child-channel message, in submission order, while the state machine is in a state
    // that forbids channel messages, and release them as soon as it leaves that state. While anything is held,
    // later child writes are held too, so ordering is never changed. Held promises are only completed when the
    // message actually reaches the parent channel, or failed if the handler goes away first.
    //
    // Memory is bounded by SSH flow control: channel data can only be issued against the peer's window.
    private var childWritesHeldForKeyExchange: CircularBuffer<(message: SSHMessage, promise: EventLoopPromise<Void>?)>

    // Guards against re-entrant release: a promise completed during release may trigger another child write.
    private var isReleasingChildWritesHeldForKeyExchange: Bool = false

    /// Construct a new ``NIOSSHHandler``.
    ///
    /// - parameters:
    ///     - role: The role of this channel in the connection, client or server.
    ///     - allocator: An allocator for `ByteBuffer`s
    ///     - inboundChildChannelInitializer: A callback that will be invoked whenever the remote peer attempts to construct a new SSH channel in a connection.
    public init(
        role: SSHConnectionRole,
        allocator: ByteBufferAllocator,
        inboundChildChannelInitializer: ((Channel, SSHChannelType) -> EventLoopFuture<Void>)?
    ) {
        self.stateMachine = SSHConnectionStateMachine(role: role, protectionSchemes: role.transportProtectionSchemes)
        self.pendingWrite = false
        self.outboundFrameBuffer = allocator.buffer(capacity: 1024)
        self.pendingChannelInitializations = CircularBuffer(initialCapacity: 4)
        self.pendingGlobalRequests = CircularBuffer(initialCapacity: 4)
        self.pendingGlobalRequestResponses = CircularBuffer(initialCapacity: 4)
        self.childWritesHeldForKeyExchange = CircularBuffer(initialCapacity: 4)
        self.multiplexer = SSHChannelMultiplexer(
            delegate: self,
            allocator: allocator,
            childChannelInitializer: inboundChildChannelInitializer,
            maximumPacketSize: role.maximumPacketSize
        )
    }
}

@available(*, unavailable)
extension NIOSSHHandler: Sendable {}

extension NIOSSHHandler {
    enum PendingGlobalRequestResponse {
        case tcpForwarding(EventLoopPromise<GlobalRequest.TCPForwardingResponse?>)
        case unknown(EventLoopPromise<ByteBuffer?>)

        func succeed(_ result: SSHMessage.RequestSuccessMessage?) {
            switch self {
            case .tcpForwarding(let promise):
                promise.succeed(result.map(GlobalRequest.TCPForwardingResponse.init))
            case .unknown(let promise):
                promise.succeed(result?.buffer)
            }
        }

        func fail(_ error: Error) {
            switch self {
            case .tcpForwarding(let promise):
                promise.fail(error)
            case .unknown(let promise):
                promise.fail(error)
            }
        }
    }
}

extension NIOSSHHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias InboundOut = Never  // Temporary
    public typealias OutboundIn = Never  // Temporary

    public func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        if context.channel.isActive {
            self.initialize(context: context)
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil

        // We don't actually need to nil out the multiplexer here (it will nil its reference to us)
        // but we _can_, and it doesn't hurt.
        self.multiplexer?.parentHandlerRemoved()
        self.multiplexer = nil

        self.dropAllPendingGlobalRequests(ChannelError.eof)
        self.dropUnsatisfiedGlobalRequests(ChannelError.eof)
        while let next = self.pendingChannelInitializations.popFirst() {
            next.promise?.fail(ChannelError.eof)
        }

        // BRIZMO PATCH (#250): writes still held for a key re-exchange can never be sent now; fail them rather than
        // leaving their promises dangling. `self.context` is already nil, so anything a failure callback writes is
        // failed immediately by `writeFromChildChannel`.
        while let held = self.childWritesHeldForKeyExchange.popFirst() {
            held.promise?.fail(ChannelError.eof)
        }
    }

    public func channelActive(context: ChannelHandlerContext) {
        self.initialize(context: context)
    }

    private func initialize(context: ChannelHandlerContext) {
        // The connection is active, let's go yo. We have to flush here.
        if let message = self.stateMachine.start() {
            do {
                try self.writeMessage(message, context: context)
                self.pendingWrite = false
                context.flush()
                context.fireChannelActive()
            } catch {
                context.fireErrorCaught(error)
            }
        }
    }

    public func channelInactive(context: ChannelHandlerContext) {
        self.multiplexer?.parentChannelInactive()
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        self.expectingChannelReadComplete = true

        var data = self.unwrapInboundIn(data)
        self.stateMachine.bufferInboundData(&data)

        do {
            while let result = try self.stateMachine.processInboundMessage(
                allocator: context.channel.allocator,
                loop: context.eventLoop
            ) {
                try self.processInboundMessageResult(result, context: context)

                // BRIZMO PATCH (#250): processing this message may have written our NEWKEYS (server role: it is
                // emitted together with the key exchange reply) or a disconnect; either way held child writes may
                // be releasable now. The flush happens in channelReadComplete, as for every write in this loop.
                self.releaseChildWritesHeldForKeyExchangeIfPossible(context: context)
            }
        } catch {
            context.fireErrorCaught(error)
        }
    }

    public func channelReadComplete(context: ChannelHandlerContext) {
        self.multiplexer?.parentChannelReadComplete()
        self.expectingChannelReadComplete = false

        if self.pendingWrite {
            self.pendingWrite = false
            context.flush()
        }

        self.createPendingChannelsIfPossible()
        self.sendGlobalRequestsIfPossible()
    }

    private func writeMessage(
        _ multiMessage: SSHMultiMessage,
        context: ChannelHandlerContext,
        promise: EventLoopPromise<Void>? = nil
    ) throws {
        self.outboundFrameBuffer.clear()

        for message in multiMessage {
            try self.stateMachine.processOutboundMessage(
                message,
                buffer: &self.outboundFrameBuffer,
                allocator: context.channel.allocator,
                loop: context.eventLoop
            )
            self.pendingWrite = true
        }

        context.write(self.wrapOutboundOut(self.outboundFrameBuffer), promise: promise)
    }

    private func processInboundMessageResult(
        _ result: SSHConnectionStateMachine.StateMachineInboundProcessResult,
        context: ChannelHandlerContext
    ) throws {
        switch result {
        case .emitMessage(let message):
            try self.writeMessage(message, context: context)
        case .noMessage:
            break
        case .possibleFutureMessage(let future):
            // TODO(cory): This is not right, but for now it's good enough.
            future.hop(to: context.eventLoop).assumeIsolatedUnsafeUnchecked().whenComplete { result in
                switch result {
                case .success(.some(let message)):
                    do {
                        try self.writeMessage(message, context: context)
                        // BRIZMO PATCH (#250): client role sends NEWKEYS from here, after host key validation,
                        // which may complete long after the read loop. Release held child writes before the flush.
                        self.releaseChildWritesHeldForKeyExchangeIfPossible(context: context)
                        self.pendingWrite = false
                        context.flush()
                    } catch {
                        context.fireErrorCaught(error)
                    }
                case .success(.none):
                    // Do nothing
                    break
                case .failure(let error):
                    context.fireErrorCaught(error)
                }
            }
        case .forwardToMultiplexer(let message):
            try self.multiplexer?.receiveMessage(message)
        case .globalRequest(let message):
            try self.handleGlobalRequest(message)
        case .globalRequestResponse(let response):
            try self.handleGlobalRequestResponse(response)
        case .disconnect:
            // Welp, we immediately have to close.
            context.close(promise: nil)
        case .event(let event):
            context.fireUserInboundEventTriggered(event)
        }
    }
}

// MARK: Create a child channel

extension NIOSSHHandler {
    /// Creates an SSH channel.
    ///
    /// This function is **not** thread-safe: it may only be called from on the channel.
    ///
    /// - parameters:
    ///     - promise: An `EventLoopPromise` that will be fulfilled with the channel when it becomes active.
    ///     - channelType: The type of the channel to create. Defaults to ``SSHChannelType/session`` for running remote processes.
    ///     - channelInitializer: A callback that will be invoked to initialize the channel.
    public func createChannel(
        _ promise: EventLoopPromise<Channel>? = nil,
        channelType: SSHChannelType = .session,
        _ channelInitializer: ((Channel, SSHChannelType) -> EventLoopFuture<Void>)?
    ) {
        self.pendingChannelInitializations.append(
            (promise: promise, channelType: channelType, initializer: channelInitializer)
        )
        self.createPendingChannelsIfPossible()
    }

    private func createPendingChannelsIfPossible() {
        guard self.stateMachine.hasActivated, self.pendingChannelInitializations.count > 0 else {
            // No work to do
            return
        }

        if !self.stateMachine.disconnected, let multiplexer = self.multiplexer {
            while let next = self.pendingChannelInitializations.popFirst() {
                multiplexer.createChildChannel(next.promise, channelType: next.channelType, next.initializer)
            }
        } else {
            while let next = self.pendingChannelInitializations.popFirst() {
                next.promise?.fail(NIOSSHError.creatingChannelAfterClosure)
            }
        }
    }
}

// MARK: Create a global request

extension NIOSSHHandler {
    /// Send a TCP forwarding request, either to initiate or cancel remote TCP forwarding.
    ///
    /// This function is **not** thread-safe: it may only be called from on the channel.
    ///
    /// - parameters:
    ///     - request: The request to send.
    ///     - promise: An `EventLoopPromise` that will be fulfilled when the request is accepted. Will error
    ///         if the request was rejected or could not be sent.
    public func sendTCPForwardingRequest(
        _ request: GlobalRequest.TCPForwardingRequest,
        promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse?>? = nil
    ) {
        let message = SSHMessage.GlobalRequestMessage(wantReply: true, type: .init(request))
        self.pendingGlobalRequests.append((value: message, promise: promise.map { .tcpForwarding($0) }))
        self.sendGlobalRequestsIfPossible()
    }

    /// Sends a global request of any kind. This is commonly used for TCP forwarding requests, but can be used to extend the protocol.
    ///
    /// This function is **not** thread-safe: it may only be called from on the channel.
    func sendGlobalRequestMessage(
        _ message: SSHMessage.GlobalRequestMessage,
        promise: EventLoopPromise<ByteBuffer?>? = nil
    ) {
        self.pendingGlobalRequests.append((value: message, promise: promise.map { .unknown($0) }))
        self.sendGlobalRequestsIfPossible()
    }

    fileprivate func dropAllPendingGlobalRequests(_ error: Error) {
        while let next = self.pendingGlobalRequests.popFirst() {
            next.1?.fail(error)
        }
    }

    fileprivate func dropUnsatisfiedGlobalRequests(_ error: Error) {
        while let next = self.pendingGlobalRequestResponses.popFirst() {
            next?.fail(error)
        }
    }

    fileprivate func handleGlobalRequestResponse(
        _ response: SSHConnectionStateMachine.StateMachineInboundProcessResult.GlobalRequestResponse
    ) throws {
        guard let next = self.pendingGlobalRequestResponses.popFirst() else {
            throw NIOSSHError.unexpectedGlobalRequestResponse
        }

        switch response {
        case .success(let response):
            next?.succeed(response)
        case .failure:
            next?.fail(NIOSSHError.globalRequestRefused)
        }
    }

    fileprivate func handleGlobalRequest(_ message: SSHMessage.GlobalRequestMessage) throws {
        guard let context = context else {
            // Weird, somehow we're out of the channel now. Drop this.
            return
        }

        // It is defined but not initialized here so that code related to this promise isn't written twice
        // The `unknown` statement needs to return so that this promise isn't used before initialization
        // It cannot be initialized here, because that would lead to a leaked promise
        let responsePromise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>

        switch message.type {
        case .unknown:
            if message.wantReply {
                // There's no way to tell what message this is and how to respond from here.
                // The only reasonable solution is to reply `SSH_MSG_REQUEST_FAILURE`
                try self.writeMessage(.init(.requestFailure), context: context)
            }
            return
        case .tcpipForward(let host, let port):
            responsePromise = context.eventLoop.makePromise()

            switch self.stateMachine.role {
            case .client(let config):
                config.globalRequestDelegate.tcpForwardingRequest(
                    .listen(host: host, port: Int(port)),
                    handler: self,
                    promise: responsePromise
                )
            case .server(let config):
                config.globalRequestDelegate.tcpForwardingRequest(
                    .listen(host: host, port: Int(port)),
                    handler: self,
                    promise: responsePromise
                )
            }
        case .cancelTcpipForward(let host, let port):
            responsePromise = context.eventLoop.makePromise()

            switch self.stateMachine.role {
            case .client(let config):
                config.globalRequestDelegate.tcpForwardingRequest(
                    .cancel(host: host, port: Int(port)),
                    handler: self,
                    promise: responsePromise
                )
            case .server(let config):
                config.globalRequestDelegate.tcpForwardingRequest(
                    .cancel(host: host, port: Int(port)),
                    handler: self,
                    promise: responsePromise
                )
            }
        }

        // The promise is created a few lines above on the context's event loop, so this is safe.
        responsePromise.futureResult.assumeIsolatedUnsafeUnchecked().whenComplete { result in
            guard message.wantReply else {
                // Nothing to do.
                return
            }

            do {
                switch result {
                case .success(let tcpForwardingResponse):
                    try self.writeMessage(
                        .init(
                            .requestSuccess(
                                .init(.tcpForwarding(tcpForwardingResponse), allocator: context.channel.allocator)
                            )
                        ),
                        context: context
                    )
                    context.flush()
                case .failure:
                    // We don't care why, we just say no.
                    try self.writeMessage(.init(.requestFailure), context: context)
                    context.flush()
                }
            } catch {
                context.fireErrorCaught(error)
            }
        }
    }

    private func sendGlobalRequestsIfPossible() {
        guard let context = self.context else {
            self.dropAllPendingGlobalRequests(ChannelError.ioOnClosedChannel)
            return
        }

        guard self.stateMachine.isActive, self.pendingGlobalRequests.count > 0 else {
            // No work to do
            return
        }

        var didSend = false
        while let next = self.pendingGlobalRequests.popFirst() {
            didSend = true
            self.sendGlobalRequest(next.0, promise: next.1, context: context)
        }

        if didSend {
            context.flush()
        }
    }

    private func sendGlobalRequest(
        _ request: SSHMessage.GlobalRequestMessage,
        promise: PendingGlobalRequestResponse?,
        context: ChannelHandlerContext
    ) {
        // Sending a single global request is tricky, because we don't want to succeed the promise until we have the result of the
        // request. That means we need a buffer of promises for request success/failure messages, as well as to create new promises.
        let writePromise = context.eventLoop.makePromise(of: Void.self)
        writePromise.futureResult.assumeIsolatedUnsafeUnchecked().whenComplete { result in
            switch result {
            case .success:
                guard self.context != nil else {
                    // This write succeeded, but we're out of the pipeline anyway. Fail the promise.
                    promise?.fail(ChannelError.eof)
                    return
                }

                if request.wantReply {
                    // Great, we're still active. Now we wait for a response.
                    // We add the nil promise here too to maintain ordering.
                    self.pendingGlobalRequestResponses.append(promise)
                } else {
                    promise?.succeed(nil)
                }
            case .failure(let error):
                promise?.fail(error)
            }
        }

        do {
            try self.writeMessage(.init(.globalRequest(request)), context: context, promise: writePromise)
        } catch {
            writePromise.fail(error)
        }
    }
}

// MARK: Initiate rekeying

extension NIOSSHHandler {
    // This function mostly exists for testing purposes: we don't initiate re-keying today because it's not
    // well-supported by evidence. But we want to be able to test against implementations who do, so we have support for
    // kicking it off.
    internal func _rekey() throws {
        // As this is test-only there are a bunch of preconditions in here, we don't really mind if we hit them in testing.
        var buffer = self.context!.channel.allocator.buffer(capacity: 1024)
        try self.stateMachine.beginRekeying(
            buffer: &buffer,
            allocator: self.context!.channel.allocator,
            loop: self.context!.eventLoop
        )
        self.context!.writeAndFlush(self.wrapOutboundOut(buffer), promise: nil)
    }
}

// MARK: Disconnect

extension NIOSSHHandler {
    // This function is for testing purposes only.
    internal func _disconnect() throws {
        // As this is test-only there are a bunch of preconditions in here, we don't really mind if we hit them in testing.
        try self.writeMessage(.init(.disconnect(.init(reason: 0, description: "", tag: ""))), context: self.context!)
        // BRIZMO PATCH (#250): we are now in `sentDisconnect`, so nothing held for a key re-exchange can ever be
        // sent. Releasing converges them: each held write fails exactly like a direct write after disconnect would.
        self.releaseChildWritesHeldForKeyExchangeIfPossible(context: self.context!)
        self.context!.flush()
    }
}

// MARK: Functions called from the multiplexer

extension NIOSSHHandler: SSHMultiplexerDelegate {
    func writeFromChildChannel(_ message: SSHMessage, _ promise: EventLoopPromise<Void>?) {
        guard let context = self.context else {
            promise?.fail(ChannelError.ioOnClosedChannel)
            return
        }

        // BRIZMO PATCH (#250): during a key re-exchange the state machine rejects channel messages; hold them
        // instead of losing them. If anything is already held, hold this one too so ordering is preserved.
        // Outside a re-key nothing is ever held, so this falls through to the unmodified upstream path.
        if self.stateMachine.isKeyExchangeBlockingChannelMessages || !self.childWritesHeldForKeyExchange.isEmpty {
            self.childWritesHeldForKeyExchange.append((message: message, promise: promise))
            self.releaseChildWritesHeldForKeyExchangeIfPossible(context: context)
            return
        }

        do {
            try self.writeMessage(SSHMultiMessage(message), context: context, promise: promise)
        } catch {
            promise?.fail(error)
        }
    }

    /// BRIZMO PATCH (#250): writes held child-channel messages, oldest first, for as long as the connection state
    /// machine accepts channel messages.
    ///
    /// Each message is written exactly as `writeFromChildChannel` would have written it outside a re-key: its own
    /// promise, and on a serialization error that promise is failed and the next message is tried (for example after
    /// a disconnect every held write fails with the same error a direct write would have got).
    ///
    /// Inside `channelRead` the flush is left to `channelReadComplete` (like every other write there); otherwise we
    /// flush here, because the child channel's own flush already happened while its write was held.
    private func releaseChildWritesHeldForKeyExchangeIfPossible(context: ChannelHandlerContext) {
        guard !self.childWritesHeldForKeyExchange.isEmpty, !self.isReleasingChildWritesHeldForKeyExchange else {
            return
        }

        self.isReleasingChildWritesHeldForKeyExchange = true
        defer { self.isReleasingChildWritesHeldForKeyExchange = false }

        var wroteAny = false
        while !self.stateMachine.isKeyExchangeBlockingChannelMessages,
            let held = self.childWritesHeldForKeyExchange.popFirst()
        {
            do {
                try self.writeMessage(SSHMultiMessage(held.message), context: context, promise: held.promise)
                wroteAny = true
            } catch {
                held.promise?.fail(error)
            }
        }

        if wroteAny, !self.expectingChannelReadComplete, self.context != nil {
            self.pendingWrite = false
            context.flush()
        }
    }

    /// Test-only: the number of child-channel messages currently held back by a key re-exchange.
    internal var _childWritesHeldForKeyExchangeCount: Int {
        self.childWritesHeldForKeyExchange.count
    }

    func flushFromChildChannel() {
        // If a child channel flushes and we aren't in a channelReadComplete loop, we need to flush. Otherwise
        // we can just wait.
        if !self.expectingChannelReadComplete {
            self.context?.flush()
        }
    }
}
