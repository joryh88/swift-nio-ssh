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
// Added by the Brizmo project (2026-11-01): keyboard-interactive user authentication (RFC 4256).
// See BRIZMO-PATCH.md.
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
import NIOConcurrencyHelpers
import NIOEmbedded
import XCTest

@testable import NIOSSH

private enum KITestError: Error, Equatable {
    case bang
    /// A held promise the test never completed; failed by `tearDown` so that it cannot leak (STATIC-03).
    case unsettledAtTeardown
}

/// Every promise a test delegate holds instead of completing (STATIC-03 S3-2). The ledger keeps such promises
/// alive past the test body, and `tearDown` fails whichever ones the test left open — typically because an
/// assertion failed or a `try` threw (as mutations make them do) before the test completed them. NIO would
/// otherwise stop the whole test process with "leaking promise" when the delegate is released, instead of
/// reporting the failing test. A promise is only ever completed once: the ledger watches its future and skips
/// completed ones.
private struct HeldPromise: Sendable {
    var label: String
    var settled: NIOLoopBoundBox<Bool>
    var fail: @Sendable (Error) -> Void
}

private let heldPromiseLedger = NIOLockedValueBox<[HeldPromise]>([])

private func trackHeldPromise<Value: Sendable>(_ promise: EventLoopPromise<Value>, _ label: String) {
    let settled = NIOLoopBoundBox(false, eventLoop: promise.futureResult.eventLoop)
    promise.futureResult.whenComplete { _ in settled.value = true }
    heldPromiseLedger.withLockedValue { $0.append(HeldPromise(label: label, settled: settled, fail: { promise.fail($0) })) }
}

/// Fails every held promise still open and returns their labels (empty when the test completed them all).
private func settleHeldPromises() -> [String] {
    let held = heldPromiseLedger.withLockedValue { ledger -> [HeldPromise] in
        defer { ledger = [] }
        return ledger
    }
    var left: [String] = []
    for entry in held where !entry.settled.value {
        left.append(entry.label)
        entry.fail(KITestError.unsettledAtTeardown)
    }
    return left
}

/// A client delegate driven by a script of offers; challenges are answered by `answer`.
private final class ScriptedKeyboardInteractiveClientDelegate: NIOSSHClientUserAuthenticationDelegate {
    enum Step {
        case offer(NIOSSHUserAuthenticationOffer.Offer)
        case noMoreOffers
        case fail(Error)
        /// Keep the promise in `heldOffer`; the test completes it later.
        case hold
    }

    private var steps: [Step]
    private let answer: (NIOSSHKeyboardInteractiveChallenge) -> Result<NIOSSHKeyboardInteractiveResponse, Error>

    /// When true, challenges are not answered: their promises go to `heldChallenges`.
    var holdChallenges = false

    private(set) var availableMethodsSeen: [NIOSSHAvailableUserAuthenticationMethods] = []
    private(set) var serverNamesSeen: [[String]] = []
    private(set) var challengesSeen: [NIOSSHKeyboardInteractiveChallenge] = []
    private(set) var heldOffer: EventLoopPromise<NIOSSHUserAuthenticationOffer?>?
    private(set) var heldChallenges: [EventLoopPromise<NIOSSHKeyboardInteractiveResponse>] = []

    init(
        steps: [Step],
        answer: @escaping (NIOSSHKeyboardInteractiveChallenge) -> Result<NIOSSHKeyboardInteractiveResponse, Error>
    ) {
        self.steps = steps
        self.answer = answer
    }

    // Required by the protocol; NIOSSH calls the names-carrying variant below instead.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        XCTFail("NIOSSH must call nextAuthenticationType(availableMethods:serverOfferedMethodNames:nextChallengePromise:)")
        self.nextAuthenticationType(
            availableMethods: availableMethods,
            serverOfferedMethodNames: [],
            nextChallengePromise: nextChallengePromise
        )
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        serverOfferedMethodNames: [String],
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        self.availableMethodsSeen.append(availableMethods)
        self.serverNamesSeen.append(serverOfferedMethodNames)
        guard !self.steps.isEmpty else {
            nextChallengePromise.succeed(nil)
            return
        }
        switch self.steps.removeFirst() {
        case .offer(let offer):
            nextChallengePromise.succeed(.init(username: "foo", serviceName: "", offer: offer))
        case .noMoreOffers:
            nextChallengePromise.succeed(nil)
        case .fail(let error):
            nextChallengePromise.fail(error)
        case .hold:
            trackHeldPromise(nextChallengePromise, "client held offer")
            self.heldOffer = nextChallengePromise
        }
    }

    func keyboardInteractiveChallengeReceived(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveResponse>
    ) {
        self.challengesSeen.append(challenge)
        if self.holdChallenges {
            trackHeldPromise(responsePromise, "client held challenge")
            self.heldChallenges.append(responsePromise)
            return
        }
        responsePromise.completeWith(self.answer(challenge))
    }
}

/// A client delegate written before keyboard-interactive existed: it does not implement the challenge callback.
private final class LegacyKeyboardInteractiveOfferingClientDelegate: NIOSSHClientUserAuthenticationDelegate {
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        nextChallengePromise.succeed(.init(username: "foo", serviceName: "", offer: .keyboardInteractive(.init())))
    }
}

/// A server delegate that asks `challenges` in order and expects `expectedResponses[round]` to each of them.
private final class KeyboardInteractiveServerDelegate: NIOSSHServerUserAuthenticationDelegate {
    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods
    private let challenges: [NIOSSHKeyboardInteractiveChallenge]
    private let expectedResponses: [[String]]
    private var round = 0

    private(set) var plainRequests: [NIOSSHUserAuthenticationRequest] = []
    private(set) var keyboardInteractiveRequests: [NIOSSHUserAuthenticationRequest] = []
    private(set) var responsesSeen: [(username: String, responses: [String])] = []

    init(
        supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods,
        challenges: [NIOSSHKeyboardInteractiveChallenge],
        expectedResponses: [[String]]
    ) {
        precondition(challenges.count == expectedResponses.count)
        self.supportedAuthenticationMethods = supportedAuthenticationMethods
        self.challenges = challenges
        self.expectedResponses = expectedResponses
    }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        self.plainRequests.append(request)
        responsePromise.succeed(.failure)
    }

    func keyboardInteractiveRequestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    ) {
        self.keyboardInteractiveRequests.append(request)
        self.round = 0
        responsePromise.succeed(.challenge(self.challenges[0]))
    }

    func keyboardInteractiveResponseReceived(
        username: String,
        response: NIOSSHKeyboardInteractiveResponse,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    ) {
        self.responsesSeen.append((username: username, responses: response.responses))
        guard response.responses == self.expectedResponses[self.round] else {
            responsePromise.succeed(.outcome(.failure))
            return
        }
        self.round += 1
        if self.round < self.challenges.count {
            responsePromise.succeed(.challenge(self.challenges[self.round]))
        } else {
            responsePromise.succeed(.outcome(.success))
        }
    }
}

/// A server delegate written before keyboard-interactive existed, but advertising it anyway.
private final class LegacyServerDelegate: NIOSSHServerUserAuthenticationDelegate {
    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods
    private(set) var requests: [NIOSSHUserAuthenticationRequest] = []

    init(supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods) {
        self.supportedAuthenticationMethods = supportedAuthenticationMethods
    }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        self.requests.append(request)
        responsePromise.succeed(.success)
    }
}

/// A server delegate whose keyboard-interactive callbacks can be held (promises kept for the test) or answered
/// automatically: requests with the password challenge, responses with success iff the answer is "secret".
/// Plain requests always fail.
private final class ControllableKeyboardInteractiveServerDelegate: NIOSSHServerUserAuthenticationDelegate {
    struct Held<Value> {
        var username: String
        var responses: [String]
        var promise: EventLoopPromise<Value>
    }

    let supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods
    var holdRequests: Bool
    var holdResponses: Bool
    /// What plain (non keyboard-interactive) requests get.
    var plainOutcome: NIOSSHUserAuthenticationOutcome = .failure

    private(set) var plainRequests: [NIOSSHUserAuthenticationRequest] = []
    private(set) var heldRequests: [Held<NIOSSHKeyboardInteractiveServerStep>] = []
    private(set) var heldResponses: [Held<NIOSSHKeyboardInteractiveServerStep>] = []
    private(set) var responseUsernames: [String] = []

    init(supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods, holdRequests: Bool, holdResponses: Bool) {
        self.supportedAuthenticationMethods = supportedAuthenticationMethods
        self.holdRequests = holdRequests
        self.holdResponses = holdResponses
    }

    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    ) {
        self.plainRequests.append(request)
        responsePromise.succeed(self.plainOutcome)
    }

    func keyboardInteractiveRequestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    ) {
        if self.holdRequests {
            trackHeldPromise(responsePromise, "server held keyboard-interactive request (\(request.username))")
            self.heldRequests.append(.init(username: request.username, responses: [], promise: responsePromise))
        } else {
            responsePromise.succeed(.challenge(KIFixtures.passwordChallenge))
        }
    }

    func keyboardInteractiveResponseReceived(
        username: String,
        response: NIOSSHKeyboardInteractiveResponse,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    ) {
        self.responseUsernames.append(username)
        if self.holdResponses {
            trackHeldPromise(responsePromise, "server held keyboard-interactive response (\(username))")
            self.heldResponses.append(.init(username: username, responses: response.responses, promise: responsePromise))
        } else {
            responsePromise.succeed(.outcome(response.responses == ["secret"] ? .success : .failure))
        }
    }
}

/// Two connection state machines driven against each other in memory (no channel, no handler), with message
/// queues that survive between `pump()` calls so that futures completed later still deliver their messages.
private final class ConnectionPair {
    var client: SSHConnectionStateMachine
    var server: SSHConnectionStateMachine
    let loop: EmbeddedEventLoop
    let toSendFromClient: NIOLoopBoundBox<[SSHMultiMessage]>
    let toSendFromServer: NIOLoopBoundBox<[SSHMultiMessage]>
    /// Failures of `possibleFutureMessage` futures on either side (an error the handler would fire).
    let futureErrors: NIOLoopBoundBox<[String]>
    /// Every message the server state machine has written, in order.
    private(set) var sentByServer: [SSHMessage] = []
    private let allocator = ByteBufferAllocator()

    init(
        client: NIOSSHClientUserAuthenticationDelegate,
        server: NIOSSHServerUserAuthenticationDelegate,
        hostKey: NIOSSHPrivateKey,
        loop: EmbeddedEventLoop
    ) {
        self.client = SSHConnectionStateMachine(
            role: .client(.init(userAuthDelegate: client, serverAuthDelegate: AcceptAllHostKeysDelegate()))
        )
        self.server = SSHConnectionStateMachine(
            role: .server(.init(hostKeys: [hostKey], userAuthDelegate: server))
        )
        self.loop = loop
        self.toSendFromClient = NIOLoopBoundBox([], eventLoop: loop)
        self.toSendFromServer = NIOLoopBoundBox([], eventLoop: loop)
        self.futureErrors = NIOLoopBoundBox([], eventLoop: loop)
        if let first = self.client.start() {
            self.toSendFromClient.value.append(first)
        }
        if let first = self.server.start() {
            self.toSendFromServer.value.append(first)
        }
    }

    /// Exchanges messages until neither side has anything left to send.
    func pump(file: StaticString = #filePath, line: UInt = #line) throws {
        for _ in 0..<500 {
            self.loop.run()
            let fromClient = self.toSendFromClient.value
            let fromServer = self.toSendFromServer.value
            self.toSendFromClient.value = []
            self.toSendFromServer.value = []
            if fromClient.isEmpty && fromServer.isEmpty {
                return
            }

            var clientBytes = self.allocator.buffer(capacity: 1024)
            var serverBytes = self.allocator.buffer(capacity: 1024)
            for multi in fromClient {
                for message in multi {
                    try self.client.processOutboundMessage(
                        message,
                        buffer: &clientBytes,
                        allocator: self.allocator,
                        loop: self.loop
                    )
                }
            }
            for multi in fromServer {
                for message in multi {
                    self.sentByServer.append(message)
                    try self.server.processOutboundMessage(
                        message,
                        buffer: &serverBytes,
                        allocator: self.allocator,
                        loop: self.loop
                    )
                }
            }
            if clientBytes.readableBytes > 0 {
                self.server.bufferInboundData(&clientBytes)
            }
            if serverBytes.readableBytes > 0 {
                self.client.bufferInboundData(&serverBytes)
            }
            try Self.drain(
                &self.client,
                into: self.toSendFromClient,
                errors: self.futureErrors,
                allocator: self.allocator,
                loop: self.loop
            )
            try Self.drain(
                &self.server,
                into: self.toSendFromServer,
                errors: self.futureErrors,
                allocator: self.allocator,
                loop: self.loop
            )
        }
        XCTFail("connection pair did not settle", file: file, line: line)
    }

    private static func drain(
        _ machine: inout SSHConnectionStateMachine,
        into queue: NIOLoopBoundBox<[SSHMultiMessage]>,
        errors: NIOLoopBoundBox<[String]>,
        allocator: ByteBufferAllocator,
        loop: EmbeddedEventLoop
    ) throws {
        while let result = try machine.processInboundMessage(allocator: allocator, loop: loop) {
            switch result {
            case .emitMessage(let message):
                queue.value.append(message)
            case .possibleFutureMessage(let future):
                future.whenComplete { result in
                    switch result {
                    case .success(.some(let message)):
                        queue.value.append(message)
                    case .success(.none):
                        break
                    case .failure(let error):
                        errors.value.append("\(error)")
                    }
                }
            case .noMessage, .event:
                break
            case .disconnect:
                return
            case .forwardToMultiplexer, .globalRequest, .globalRequestResponse:
                XCTFail("unexpected inbound result \(result)")
            }
        }
    }
}

private enum KIFixtures {
    static var passwordChallenge: NIOSSHKeyboardInteractiveChallenge {
        NIOSSHKeyboardInteractiveChallenge(prompts: [.init(text: "Password: ", echo: false)])
    }

    static var passwordChallengeMessage: SSHMessage.UserAuthInfoRequestMessage {
        SSHMessage.UserAuthInfoRequestMessage(
            name: "",
            instruction: "",
            languageTag: "",
            prompts: [.init(prompt: "Password: ", echo: false)]
        )
    }

    static var keyboardInteractiveRequest: SSHMessage.UserAuthRequestMessage {
        SSHMessage.UserAuthRequestMessage(
            username: "foo",
            service: "ssh-connection",
            method: .keyboardInteractive(submethods: [])
        )
    }

    static var passwordRequest: SSHMessage.UserAuthRequestMessage {
        SSHMessage.UserAuthRequestMessage(username: "foo", service: "ssh-connection", method: .password("bar"))
    }

    static func answerEveryPrompt(with value: String) -> (NIOSSHKeyboardInteractiveChallenge) -> Result<
        NIOSSHKeyboardInteractiveResponse, Error
    > {
        { challenge in .success(.init(responses: challenge.prompts.map { _ in value })) }
    }

    static func sshString(_ value: String) -> [UInt8] {
        let bytes = Array(value.utf8)
        let length = UInt32(bytes.count)
        return [
            UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length),
        ] + bytes
    }

    static func uint32(_ value: UInt32) -> [UInt8] {
        [
            UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
            UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value),
        ]
    }
}

final class KeyboardInteractiveAuthTests: XCTestCase {
    private var loop: EmbeddedEventLoop!
    private var hostKey: NIOSSHPrivateKey!
    private var sessionID: ByteBuffer!
    private var channel: BackToBackEmbeddedChannel!

    override func setUp() {
        self.loop = EmbeddedEventLoop()
        self.hostKey = NIOSSHPrivateKey(ed25519Key: Curve25519.Signing.PrivateKey())
        var buffer = ByteBufferAllocator().buffer(capacity: 32)
        buffer.writeBytes(0..<32)
        self.sessionID = buffer
        // Created only by the end-to-end tests (`configure(client:server:)`).
        self.channel = nil
    }

    override func tearDown() {
        // STATIC-03 S3-2: settle held promises first, while their event loops are still up.
        let unsettled = settleHeldPromises()
        if !unsettled.isEmpty {
            XCTFail("test left held promises open (failed them at teardown): \(unsettled)")
        }
        if let channel = self.channel {
            try? channel.finish()
        }
        self.channel = nil
        try! self.loop.syncShutdownGracefully()
        self.loop = nil
        self.hostKey = nil
    }

    // MARK: - Helpers

    /// Runs the embedded loop and returns the future's result (nil if it never completed).
    private func resolve<T>(_ future: EventLoopFuture<T>) -> Result<T, Error>? {
        let box = NIOLoopBoundBox<Result<T, Error>?>(nil, eventLoop: future.eventLoop)
        future.whenComplete { box.value = $0 }
        self.loop.run()
        return box.value
    }

    private func assertRoundTrips(
        _ message: SSHMessage,
        context: SSHPacketParser.UserAuthMessageContext,
        file: StaticString = #filePath,
        line: UInt = #line
    ) throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 256)
        buffer.writeSSHMessage(message)
        XCTAssertEqual(try buffer.readSSHMessage(userAuthContext: context), message, file: file, line: line)
        XCTAssertEqual(buffer.readableBytes, 0, file: file, line: line)

        // Every strict prefix reads as "not enough bytes yet" and leaves the reader index alone.
        var whole = ByteBufferAllocator().buffer(capacity: 256)
        whole.writeSSHMessage(message)
        let bytes = Array(whole.readableBytesView)
        var partial = ByteBufferAllocator().buffer(capacity: 256)
        for byte in bytes.dropLast() {
            partial.writeInteger(byte)
            XCTAssertNil(try partial.readSSHMessage(userAuthContext: context), file: file, line: line)
            XCTAssertEqual(partial.readerIndex, 0, file: file, line: line)
        }
        partial.writeInteger(bytes.last!)
        XCTAssertEqual(try partial.readSSHMessage(userAuthContext: context), message, file: file, line: line)
    }

    private func feedVersion(to parser: inout SSHPacketParser) throws {
        var version = ByteBuffer.of(string: "SSH-2.0-OpenSSH_7.9\r\n")
        parser.append(bytes: &version)
        guard case .some(.version) = try parser.nextPacket() else {
            XCTFail("Expecting .version")
            return
        }
    }

    private func makeClient(_ delegate: NIOSSHClientUserAuthenticationDelegate) -> UserAuthenticationStateMachine {
        UserAuthenticationStateMachine(
            role: .client(.init(userAuthDelegate: delegate, serverAuthDelegate: AcceptAllHostKeysDelegate())),
            loop: self.loop,
            sessionID: self.sessionID
        )
    }

    /// Takes a client state machine through the service request dance; returns the delegate's first offer.
    private func clientAfterServiceAccept(
        _ stateMachine: inout UserAuthenticationStateMachine
    ) throws -> SSHMessage.UserAuthRequestMessage? {
        XCTAssertNotNil(stateMachine.beginAuthentication())
        stateMachine.sendServiceRequest(.init(service: "ssh-userauth"))
        let future = try XCTUnwrap(try stateMachine.receiveServiceAccept(.init(service: "ssh-userauth")))
        return try XCTUnwrap(self.resolve(future)).get()
    }

    /// Client with a keyboard-interactive request in flight (after a `none` probe that the server rejected).
    private func clientWithKeyboardInteractiveInFlight(
        _ delegate: ScriptedKeyboardInteractiveClientDelegate
    ) throws -> UserAuthenticationStateMachine {
        var stateMachine = self.makeClient(delegate)
        let probe = try XCTUnwrap(try self.clientAfterServiceAccept(&stateMachine))
        XCTAssertEqual(probe.method, .none)
        stateMachine.sendUserAuthRequest(probe)

        let failure = SSHMessage.UserAuthFailureMessage(authentications: ["keyboard-interactive"], partialSuccess: false)
        let next = try XCTUnwrap(try stateMachine.receiveUserAuthFailure(failure))
        let request = try XCTUnwrap(try XCTUnwrap(self.resolve(next)).get())
        XCTAssertEqual(request.method, .keyboardInteractive(submethods: []))
        stateMachine.sendUserAuthRequest(request)
        return stateMachine
    }

    private func makeServer(
        _ delegate: NIOSSHServerUserAuthenticationDelegate,
        maxAuthAttempts: Int? = nil
    ) throws -> UserAuthenticationStateMachine {
        var configuration = SSHServerConfiguration(hostKeys: [self.hostKey], userAuthDelegate: delegate)
        configuration.maxAuthAttempts = maxAuthAttempts
        var stateMachine = UserAuthenticationStateMachine(
            role: .server(configuration),
            loop: self.loop,
            sessionID: self.sessionID
        )
        let accept = try stateMachine.receiveServiceRequest(.init(service: "ssh-userauth"))
        XCTAssertEqual(accept, .init(service: "ssh-userauth"))
        stateMachine.sendServiceAccept(.init(service: "ssh-userauth"))
        return stateMachine
    }

    private func serverStep(
        _ future: EventLoopFuture<NIOSSHUserAuthenticationServerStepMessage>?
    ) throws -> NIOSSHUserAuthenticationServerStepMessage {
        try XCTUnwrap(self.resolve(try XCTUnwrap(future))).get()
    }

    private func assertProtocolViolation<T>(
        _ body: @autoclosure () throws -> T,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        XCTAssertThrowsError(try body(), file: file, line: line) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation, file: file, line: line)
        }
    }

    // MARK: - T1 wire round trips

    func testInfoRequestRoundTripsWithZeroOneAndThreePrompts() throws {
        let promptSets: [[SSHMessage.UserAuthInfoRequestMessage.Prompt]] = [
            [],
            [.init(prompt: "Password: ", echo: false)],
            [
                .init(prompt: "User: ", echo: true),
                .init(prompt: "Password: ", echo: false),
                .init(prompt: "Code (時間): ", echo: true),
            ],
        ]
        for prompts in promptSets {
            let message = SSHMessage.userAuthInfoRequest(
                .init(name: "Sony", instruction: "Enter the camera credentials", languageTag: "", prompts: prompts)
            )
            try self.assertRoundTrips(message, context: .keyboardInteractive)
        }
    }

    func testInfoResponseRoundTripsWithZeroOneAndThreeResponsesInEveryContext() throws {
        for responses in [[], ["secret"], ["a", "", "ü"]] {
            let message = SSHMessage.userAuthInfoResponse(.init(responses: responses))
            try self.assertRoundTrips(message, context: .default)
            try self.assertRoundTrips(message, context: .keyboardInteractive)
        }
    }

    func testKeyboardInteractiveUserAuthRequestRoundTrips() throws {
        for submethods in [[], ["pam", "bsdauth"]] {
            let message = SSHMessage.userAuthRequest(
                .init(username: "foo", service: "ssh-connection", method: .keyboardInteractive(submethods: submethods))
            )
            try self.assertRoundTrips(message, context: .default)
            try self.assertRoundTrips(message, context: .keyboardInteractive)
        }
    }

    func testWireLayoutMatchesRFC4256() throws {
        // RFC 4256 §3.1: "keyboard-interactive", string language tag (empty), string submethods.
        var request = ByteBufferAllocator().buffer(capacity: 128)
        request.writeSSHMessage(
            .userAuthRequest(
                .init(username: "foo", service: "ssh-connection", method: .keyboardInteractive(submethods: ["pam", "bsdauth"]))
            )
        )
        XCTAssertEqual(
            Array(request.readableBytesView),
            [50] + KIFixtures.sshString("foo") + KIFixtures.sshString("ssh-connection")
                + KIFixtures.sshString("keyboard-interactive") + KIFixtures.sshString("")
                + KIFixtures.sshString("pam,bsdauth")
        )

        // RFC 4256 §3.2.
        var info = ByteBufferAllocator().buffer(capacity: 128)
        info.writeSSHMessage(
            .userAuthInfoRequest(
                .init(
                    name: "n",
                    instruction: "i",
                    languageTag: "",
                    prompts: [.init(prompt: "P1", echo: false), .init(prompt: "P2", echo: true)]
                )
            )
        )
        XCTAssertEqual(
            Array(info.readableBytesView),
            [60] + KIFixtures.sshString("n") + KIFixtures.sshString("i") + KIFixtures.sshString("")
                + KIFixtures.uint32(2) + KIFixtures.sshString("P1") + [0] + KIFixtures.sshString("P2") + [1]
        )

        // RFC 4256 §3.4.
        var response = ByteBufferAllocator().buffer(capacity: 64)
        response.writeSSHMessage(.userAuthInfoResponse(.init(responses: ["x", "yz"])))
        XCTAssertEqual(
            Array(response.readableBytesView),
            [61] + KIFixtures.uint32(2) + KIFixtures.sshString("x") + KIFixtures.sshString("yz")
        )
    }

    func testHostilePromptCountReadsAsIncompleteInsteadOfAllocating() throws {
        var buffer = ByteBufferAllocator().buffer(capacity: 64)
        buffer.writeBytes(
            [60] + KIFixtures.sshString("") + KIFixtures.sshString("") + KIFixtures.sshString("")
                + KIFixtures.uint32(0xFFFF_FFFF) + KIFixtures.sshString("only one") + [0]
        )
        XCTAssertNil(try buffer.readSSHMessage(userAuthContext: .keyboardInteractive))
        XCTAssertEqual(buffer.readerIndex, 0)

        var responses = ByteBufferAllocator().buffer(capacity: 16)
        responses.writeBytes([61] + KIFixtures.uint32(0xFFFF_FFFF))
        XCTAssertNil(try responses.readSSHMessage())
        XCTAssertEqual(responses.readerIndex, 0)
    }

    // MARK: - T2 message number 60

    func testSixtyIsPKOKByDefaultAndInfoRequestOnlyInKeyboardInteractiveContext() throws {
        let pkOK = SSHMessage.userAuthPKOK(.init(key: NIOSSHPrivateKey(ed25519Key: .init()).publicKey))
        var pkOKBytes = ByteBufferAllocator().buffer(capacity: 256)
        pkOKBytes.writeSSHMessage(pkOK)

        // Default context: upstream behaviour.
        var defaultRead = pkOKBytes
        XCTAssertEqual(try defaultRead.readSSHMessage(), pkOK)
        defaultRead = pkOKBytes
        XCTAssertEqual(try defaultRead.readSSHMessage(userAuthContext: .default), pkOK)

        // Keyboard-interactive context: the same bytes are not a PK_OK (they are an incomplete INFO_REQUEST).
        var kiRead = pkOKBytes
        XCTAssertNil(try kiRead.readSSHMessage(userAuthContext: .keyboardInteractive))
        XCTAssertEqual(kiRead.readerIndex, pkOKBytes.readerIndex)

        // INFO_REQUEST bytes in the default context are rejected as a malformed PK_OK.
        var infoBytes = ByteBufferAllocator().buffer(capacity: 64)
        infoBytes.writeSSHMessage(.userAuthInfoRequest(KIFixtures.passwordChallengeMessage))
        XCTAssertThrowsError(try infoBytes.readSSHMessage()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }
    }

    func testPacketParserReadsSixtyAccordingToItsUserAuthContext() throws {
        let infoRequest = SSHMessage.userAuthInfoRequest(KIFixtures.passwordChallengeMessage)
        var packet = ByteBufferAllocator().buffer(capacity: 128)
        packet.writeSSHPacket(message: infoRequest, lengthEncrypted: true, blockSize: 8)

        var defaultParser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        try self.feedVersion(to: &defaultParser)
        XCTAssertEqual(defaultParser.userAuthMessageContext, .default)
        var copy = packet
        defaultParser.append(bytes: &copy)
        XCTAssertThrowsError(try defaultParser.nextPacket()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidSSHMessage)
        }

        var kiParser = SSHPacketParser(isServer: false, allocator: ByteBufferAllocator())
        try self.feedVersion(to: &kiParser)
        kiParser.userAuthMessageContext = .keyboardInteractive
        copy = packet
        kiParser.append(bytes: &copy)
        XCTAssertEqual(try kiParser.nextPacket(), infoRequest)

        // 61 does not depend on the context.
        var responsePacket = ByteBufferAllocator().buffer(capacity: 64)
        let infoResponse = SSHMessage.userAuthInfoResponse(.init(responses: ["secret"]))
        responsePacket.writeSSHPacket(message: infoResponse, lengthEncrypted: true, blockSize: 8)
        defaultParser = SSHPacketParser(isServer: true, allocator: ByteBufferAllocator())
        try self.feedVersion(to: &defaultParser)
        defaultParser.append(bytes: &responsePacket)
        XCTAssertEqual(try defaultParser.nextPacket(), infoResponse)
    }

    // MARK: - Method set

    func testAvailableMethodsRecogniseKeyboardInteractive() {
        let parsed = NIOSSHAvailableUserAuthenticationMethods(
            SSHMessage.UserAuthFailureMessage(
                authentications: ["publickey", "keyboard-interactive", "gssapi-with-mic"],
                partialSuccess: false
            )
        )
        XCTAssertEqual(parsed, [.publicKey, .keyboardInteractive])

        let onlyKI = NIOSSHAvailableUserAuthenticationMethods(
            SSHMessage.UserAuthFailureMessage(authentications: ["keyboard-interactive"], partialSuccess: false)
        )
        XCTAssertEqual(onlyKI, .keyboardInteractive)
        XCTAssertFalse(onlyKI.isEmpty)

        XCTAssertEqual(
            NIOSSHAvailableUserAuthenticationMethods([.password, .keyboardInteractive]).strings,
            ["password", "keyboard-interactive"]
        )
        XCTAssertEqual(NIOSSHAvailableUserAuthenticationMethods.keyboardInteractive.strings, ["keyboard-interactive"])

        // `.all` is unchanged on purpose (see the doc comment on `.keyboardInteractive`).
        XCTAssertFalse(NIOSSHAvailableUserAuthenticationMethods.all.contains(.keyboardInteractive))
        XCTAssertEqual(NIOSSHAvailableUserAuthenticationMethods.all.strings, ["password", "publickey", "hostbased"])
    }

    // MARK: - T3 client state machine

    func testClientNoneProbeThenKeyboardInteractiveSucceeds() throws {
        let delegate = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "secret")
        )
        var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)
        XCTAssertEqual(delegate.availableMethodsSeen, [.all, .keyboardInteractive])

        let future = try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage)
        let response = try XCTUnwrap(self.resolve(future)).get()
        XCTAssertEqual(response, .init(responses: ["secret"]))
        XCTAssertEqual(delegate.challengesSeen, [KIFixtures.passwordChallenge])

        XCTAssertNoThrow(try stateMachine.sendUserAuthInfoResponse(response))
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    func testClientAnswersSeveralRoundsOfOneAttempt() throws {
        let delegate = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "x")
        )
        var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)

        let rounds: [[SSHMessage.UserAuthInfoRequestMessage.Prompt]] = [
            [.init(prompt: "Password: ", echo: false)],
            [],
            [.init(prompt: "A: ", echo: true), .init(prompt: "B: ", echo: false)],
        ]
        for prompts in rounds {
            let request = SSHMessage.UserAuthInfoRequestMessage(
                name: "",
                instruction: "",
                languageTag: "",
                prompts: prompts
            )
            let response = try XCTUnwrap(self.resolve(try stateMachine.receiveUserAuthInfoRequest(request))).get()
            XCTAssertEqual(response.responses, prompts.map { _ in "x" })
            XCTAssertNoThrow(try stateMachine.sendUserAuthInfoResponse(response))
        }
        XCTAssertEqual(delegate.challengesSeen.count, 3)
        XCTAssertNoThrow(try stateMachine.receiveUserAuthSuccess())
    }

    func testClientIsAskedAgainAfterKeyboardInteractiveFailure() throws {
        let delegate = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none), .offer(.keyboardInteractive(.init())), .noMoreOffers],
            answer: KIFixtures.answerEveryPrompt(with: "wrong")
        )
        var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)

        let response = try XCTUnwrap(
            self.resolve(try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))
        ).get()
        try stateMachine.sendUserAuthInfoResponse(response)

        let failure = SSHMessage.UserAuthFailureMessage(
            authentications: ["keyboard-interactive", "password"],
            partialSuccess: false
        )
        let next = try XCTUnwrap(try stateMachine.receiveUserAuthFailure(failure))
        XCTAssertNil(try XCTUnwrap(self.resolve(next)).get())
        XCTAssertEqual(delegate.availableMethodsSeen.last, [.keyboardInteractive, .password])
        stateMachine.noFurtherMethods()

        // The attempt is over: another INFO_REQUEST is not acceptable.
        self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))
    }

    func testClientRejectsInfoRequestWhenNoKeyboardInteractiveRequestIsInFlight() throws {
        let delegate = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none)],
            answer: KIFixtures.answerEveryPrompt(with: "x")
        )

        // idle
        var idle = self.makeClient(delegate)
        self.assertProtocolViolation(try idle.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))

        // awaiting the next request (nothing in flight)
        var awaiting = self.makeClient(delegate)
        _ = try self.clientAfterServiceAccept(&awaiting)
        self.assertProtocolViolation(try awaiting.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))

        // password in flight
        var password = self.makeClient(
            ScriptedKeyboardInteractiveClientDelegate(steps: [], answer: KIFixtures.answerEveryPrompt(with: "x"))
        )
        _ = try self.clientAfterServiceAccept(&password)
        password.sendUserAuthRequest(KIFixtures.passwordRequest)
        self.assertProtocolViolation(try password.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))

        // publickey in flight (60 would be PK_OK there, which this client still does not handle)
        var publicKey = self.makeClient(
            ScriptedKeyboardInteractiveClientDelegate(steps: [], answer: KIFixtures.answerEveryPrompt(with: "x"))
        )
        _ = try self.clientAfterServiceAccept(&publicKey)
        publicKey.sendUserAuthRequest(
            .init(
                username: "foo",
                service: "ssh-connection",
                method: .publicKey(.known(key: NIOSSHPrivateKey(ed25519Key: .init()).publicKey, signature: nil))
            )
        )
        self.assertProtocolViolation(try publicKey.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))
    }

    func testClientRejectsSecondInfoRequestBeforeAnsweringTheFirst() throws {
        let delegate = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "x")
        )
        var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)
        let first = try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage)
        XCTAssertNotNil(self.resolve(first))
        self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))
        XCTAssertEqual(delegate.challengesSeen.count, 1)
    }

    func testClientNeverProducesAResponseWithTheWrongCount() throws {
        let cases: [([SSHMessage.UserAuthInfoRequestMessage.Prompt], [String])] = [
            ([.init(prompt: "Password: ", echo: false)], ["a", "b"]),
            ([], ["unexpected"]),
            ([.init(prompt: "A: ", echo: true), .init(prompt: "B: ", echo: false)], ["only one"]),
        ]
        for (prompts, answers) in cases {
            let delegate = ScriptedKeyboardInteractiveClientDelegate(
                steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
                answer: { _ in .success(.init(responses: answers)) }
            )
            var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)
            let request = SSHMessage.UserAuthInfoRequestMessage(
                name: "",
                instruction: "",
                languageTag: "",
                prompts: prompts
            )
            let result = try XCTUnwrap(self.resolve(try stateMachine.receiveUserAuthInfoRequest(request)))
            XCTAssertThrowsError(try result.get()) { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .protocolViolation)
            }
        }
    }

    func testClientRejectsOutcomeWhileItsAnswerIsOutstanding() throws {
        for outcome in ["success", "failure"] {
            let delegate = ScriptedKeyboardInteractiveClientDelegate(
                steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
                answer: KIFixtures.answerEveryPrompt(with: "x")
            )
            var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)
            XCTAssertNotNil(self.resolve(try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage)))
            if outcome == "success" {
                self.assertProtocolViolation(try stateMachine.receiveUserAuthSuccess())
            } else {
                self.assertProtocolViolation(
                    try stateMachine.receiveUserAuthFailure(
                        .init(authentications: ["keyboard-interactive"], partialSuccess: false)
                    )
                )
            }
        }
    }

    func testClientRejectsInfoResponseWithoutUnansweredChallenge() throws {
        let delegate = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "x")
        )
        var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)
        self.assertProtocolViolation(try stateMachine.sendUserAuthInfoResponse(.init(responses: [])))
    }

    // MARK: - T4 server state machine

    func testServerChallengesAndAcceptsTheRightAnswer() throws {
        let delegate = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        var stateMachine = try self.makeServer(delegate)

        guard
            case .infoRequest(let challenge) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected a keyboard-interactive challenge")
            return
        }
        XCTAssertEqual(challenge, KIFixtures.passwordChallengeMessage)
        XCTAssertEqual(delegate.keyboardInteractiveRequests.map { $0.username }, ["foo"])
        XCTAssertNoThrow(try stateMachine.sendUserAuthInfoRequest(challenge))

        guard
            case .response(.success) = try self.serverStep(
                try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["secret"]))
            )
        else {
            XCTFail("Expected success")
            return
        }
        XCTAssertEqual(delegate.responsesSeen.map { $0.username }, ["foo"])
        XCTAssertEqual(delegate.responsesSeen.map { $0.responses }, [["secret"]])
        stateMachine.sendUserAuthSuccess()
    }

    func testServerAnswersWrongResponseWithFailureListingSupportedMethods() throws {
        let delegate = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: [.password, .keyboardInteractive],
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        var stateMachine = try self.makeServer(delegate)
        guard
            case .infoRequest(let challenge) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected a keyboard-interactive challenge")
            return
        }
        try stateMachine.sendUserAuthInfoRequest(challenge)

        guard
            case .response(.failure(let failure)) = try self.serverStep(
                try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["nope"]))
            )
        else {
            XCTFail("Expected failure")
            return
        }
        XCTAssertEqual(failure, .init(authentications: ["password", "keyboard-interactive"], partialSuccess: false))
        stateMachine.sendUserAuthFailure(failure)
    }

    func testServerWithoutKeyboardInteractiveAnswersFailure() throws {
        let delegate = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .password,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        var stateMachine = try self.makeServer(delegate)
        guard
            case .response(.failure(let failure)) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected failure")
            return
        }
        XCTAssertEqual(failure, .init(authentications: ["password"], partialSuccess: false))
        XCTAssertTrue(delegate.keyboardInteractiveRequests.isEmpty)
        XCTAssertTrue(delegate.plainRequests.isEmpty)
    }

    func testServerRejectsInfoResponseWithoutAnOutstandingChallenge() throws {
        let delegate = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )

        // Nothing asked yet.
        var fresh = try self.makeServer(delegate)
        self.assertProtocolViolation(try fresh.receiveUserAuthInfoResponse(.init(responses: ["secret"])))

        // Challenge decided by the delegate but not sent yet.
        var notSent = try self.makeServer(delegate)
        _ = try self.serverStep(try notSent.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest))
        self.assertProtocolViolation(try notSent.receiveUserAuthInfoResponse(.init(responses: ["secret"])))

        // Challenge already answered once.
        var answered = try self.makeServer(delegate)
        guard
            case .infoRequest(let challenge) = try self.serverStep(
                try answered.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected a keyboard-interactive challenge")
            return
        }
        try answered.sendUserAuthInfoRequest(challenge)
        _ = try self.serverStep(try answered.receiveUserAuthInfoResponse(.init(responses: ["nope"])))
        self.assertProtocolViolation(try answered.receiveUserAuthInfoResponse(.init(responses: ["secret"])))
        XCTAssertEqual(delegate.responsesSeen.count, 1)
    }

    func testServerNewRequestAbandonsOutstandingChallenge() throws {
        let delegate = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: [.password, .keyboardInteractive],
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        var stateMachine = try self.makeServer(delegate)
        guard
            case .infoRequest(let challenge) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected a keyboard-interactive challenge")
            return
        }
        try stateMachine.sendUserAuthInfoRequest(challenge)

        guard
            case .response(.failure(let failure)) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.passwordRequest)
            )
        else {
            XCTFail("Expected failure")
            return
        }
        stateMachine.sendUserAuthFailure(failure)
        self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["secret"])))
        XCTAssertTrue(delegate.responsesSeen.isEmpty)
    }

    func testServerAnswersMismatchedResponseCountWithFailureAndKeepsGoing() throws {
        let delegate = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        var stateMachine = try self.makeServer(delegate)
        guard
            case .infoRequest(let challenge) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected a keyboard-interactive challenge")
            return
        }
        try stateMachine.sendUserAuthInfoRequest(challenge)

        guard
            case .response(.failure(let failure)) = try self.serverStep(
                try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["secret", "extra"]))
            )
        else {
            XCTFail("Expected failure, not a disconnect")
            return
        }
        XCTAssertEqual(failure, .init(authentications: ["keyboard-interactive"], partialSuccess: false))
        XCTAssertTrue(delegate.responsesSeen.isEmpty, "a mismatched response must not reach the delegate")
        stateMachine.sendUserAuthFailure(failure)

        // The connection is still usable: a new attempt gets a new challenge.
        guard
            case .infoRequest = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected a new challenge")
            return
        }
    }

    func testServerInfoResponsesDoNotCountTowardMaxAuthAttempts() throws {
        let delegate = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge, KIFixtures.passwordChallenge, KIFixtures.passwordChallenge],
            expectedResponses: [["a"], ["b"], ["c"]]
        )
        var stateMachine = try self.makeServer(delegate, maxAuthAttempts: 1)

        // One USERAUTH_REQUEST, then three INFO_RESPONSE rounds: all within the single permitted attempt.
        var step = try self.serverStep(try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest))
        for (index, answer) in ["a", "b"].enumerated() {
            guard case .infoRequest(let challenge) = step else {
                XCTFail("Expected challenge \(index + 1)")
                return
            }
            try stateMachine.sendUserAuthInfoRequest(challenge)
            step = try self.serverStep(try stateMachine.receiveUserAuthInfoResponse(.init(responses: [answer])))
        }
        guard case .infoRequest(let lastChallenge) = step else {
            XCTFail("Expected challenge 3")
            return
        }
        try stateMachine.sendUserAuthInfoRequest(lastChallenge)
        guard
            case .response(.failure(let failure)) = try self.serverStep(
                try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["wrong"]))
            )
        else {
            XCTFail("Expected failure, not a disconnect")
            return
        }
        stateMachine.sendUserAuthFailure(failure)
        XCTAssertEqual(delegate.responsesSeen.count, 3)

        // The second USERAUTH_REQUEST exceeds maxAuthAttempts = 1.
        guard
            case .response(.disconnect) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected disconnect on the second request")
            return
        }
    }

    // MARK: - T6 default implementations

    func testDefaultClientImplementationFailsTheChallenge() throws {
        var stateMachine = self.makeClient(LegacyKeyboardInteractiveOfferingClientDelegate())
        let request = try XCTUnwrap(try self.clientAfterServiceAccept(&stateMachine))
        XCTAssertEqual(request.method, .keyboardInteractive(submethods: []))
        stateMachine.sendUserAuthRequest(request)

        let result = try XCTUnwrap(
            self.resolve(try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))
        )
        XCTAssertThrowsError(try result.get()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .keyboardInteractiveChallengeUnhandled)
        }
    }

    func testDefaultServerImplementationAnswersFailure() throws {
        // Advertises keyboard-interactive but only implements `requestReceived`.
        let advertising = LegacyServerDelegate(supportedAuthenticationMethods: [.password, .keyboardInteractive])
        var stateMachine = try self.makeServer(advertising)
        guard
            case .response(.failure(let failure)) = try self.serverStep(
                try stateMachine.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected failure")
            return
        }
        XCTAssertEqual(failure, .init(authentications: ["password", "keyboard-interactive"], partialSuccess: false))
        XCTAssertTrue(advertising.requests.isEmpty, "keyboard-interactive must not be routed to requestReceived")

        // An upstream delegate advertising `.all` does not offer keyboard-interactive at all.
        var denyAll = try self.makeServer(DenyAllServerAuthDelegate())
        guard
            case .response(.failure(let denyAllFailure)) = try self.serverStep(
                try denyAll.receiveUserAuthRequestStep(KIFixtures.keyboardInteractiveRequest)
            )
        else {
            XCTFail("Expected failure")
            return
        }
        XCTAssertEqual(
            denyAllFailure,
            .init(authentications: ["password", "publickey", "hostbased"], partialSuccess: false)
        )
    }

    // MARK: - T5 end to end

    private func configure(
        client: NIOSSHClientUserAuthenticationDelegate,
        server: NIOSSHServerUserAuthenticationDelegate
    ) throws -> UserEventExpecter {
        var harness = TestHarness()
        harness.clientAuthDelegate = client
        harness.serverAuthDelegate = server
        self.channel = BackToBackEmbeddedChannel()
        try self.channel.configureWithHarness(harness)
        let events = UserEventExpecter()
        try self.channel.client.pipeline.syncOperations.addHandler(events)
        return events
    }

    func testEndToEndKeyboardInteractiveAuthenticatesAndCarriesChannelData() throws {
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "secret")
        )
        let server = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        let events = try self.configure(client: client, server: server)
        try self.channel.activate()
        try self.channel.interactInMemory()

        XCTAssertTrue(events.userEvents.contains { $0 is UserAuthSuccessEvent })
        XCTAssertEqual(client.availableMethodsSeen, [.all, .keyboardInteractive])
        XCTAssertEqual(client.challengesSeen, [KIFixtures.passwordChallenge])
        XCTAssertEqual(server.plainRequests.count, 1, "the none probe")
        XCTAssertEqual(server.responsesSeen.map { $0.responses }, [["secret"]])

        let clientChild = try self.channel.createNewChannel()
        try self.channel.interactInMemory()
        let serverChild = try XCTUnwrap(self.channel.activeServerChannels.first)
        let recorder = ReadRecordingHandler()
        try serverChild.pipeline.syncOperations.addHandler(recorder)

        var payload = clientChild.allocator.buffer(capacity: 32)
        payload.writeString("ptp over keyboard-interactive")
        let written = NIOLoopBoundBox<Result<Void, Error>?>(nil, eventLoop: clientChild.eventLoop)
        clientChild.writeAndFlush(SSHChannelData(type: .channel, data: .byteBuffer(payload))).whenComplete {
            written.value = $0
        }
        try self.channel.interactInMemory()
        guard case .some(.success) = written.value else {
            XCTFail("Child channel write did not succeed: \(String(describing: written.value))")
            return
        }

        XCTAssertEqual(recorder.reads.count, 1)
        guard case .some(.byteBuffer(let received)) = recorder.reads.first?.data else {
            XCTFail("Expected channel data")
            return
        }
        XCTAssertEqual(received, payload)
    }

    func testEndToEndWrongAnswerFailsTheConnectionWithoutDanglingPromises() throws {
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.none), .offer(.keyboardInteractive(.init())), .fail(KITestError.bang)],
            answer: KIFixtures.answerEveryPrompt(with: "wrong")
        )
        let server = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        let events = try self.configure(client: client, server: server)
        let errors = ErrorLoggingHandler()
        try self.channel.client.pipeline.syncOperations.addHandler(errors)
        try self.channel.activate()

        XCTAssertThrowsError(try self.channel.interactInMemory()) { error in
            XCTAssertEqual(error as? KITestError, .bang)
        }
        XCTAssertNoThrow(try self.channel.interactInMemory())

        XCTAssertFalse(events.userEvents.contains { $0 is UserAuthSuccessEvent })
        XCTAssertEqual(errors.errors.count, 1)
        XCTAssertEqual(errors.errors.first as? KITestError, .bang)
        // Asked three times: initial, after the none probe, after the rejected answer (where it gives up).
        XCTAssertEqual(client.availableMethodsSeen, [.all, .keyboardInteractive, .keyboardInteractive])
        XCTAssertEqual(client.challengesSeen.count, 1)
        XCTAssertEqual(server.responsesSeen.map { $0.responses }, [["wrong"]])
    }

    func testEndToEndServerAsksTwoRounds() throws {
        let otp = NIOSSHKeyboardInteractiveChallenge(
            name: "Second factor",
            instruction: "Enter the code",
            prompts: [.init(text: "Code: ", echo: true)]
        )
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.keyboardInteractive(.init()))],
            answer: { challenge in
                .success(.init(responses: challenge.prompts.map { $0.text == "Code: " ? "123456" : "secret" }))
            }
        )
        let server = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge, otp],
            expectedResponses: [["secret"], ["123456"]]
        )
        let events = try self.configure(client: client, server: server)
        try self.channel.activate()
        try self.channel.interactInMemory()

        XCTAssertTrue(events.userEvents.contains { $0 is UserAuthSuccessEvent })
        XCTAssertEqual(client.challengesSeen, [KIFixtures.passwordChallenge, otp])
        XCTAssertEqual(server.responsesSeen.map { $0.responses }, [["secret"], ["123456"]])
        XCTAssertEqual(server.keyboardInteractiveRequests.count, 1)
    }

    // MARK: - F1 / R1 (STATIC-01, STATIC-02): an aborted keyboard-interactive attempt

    private func kiRequest(_ username: String) -> SSHMessage.UserAuthRequestMessage {
        .init(username: username, service: "ssh-connection", method: .keyboardInteractive(submethods: []))
    }

    private func passwordRequest(_ username: String) -> SSHMessage.UserAuthRequestMessage {
        .init(username: username, service: "ssh-connection", method: .password("pw"))
    }

    private func box<T>(_ future: EventLoopFuture<T>) -> NIOLoopBoundBox<Result<T, Error>?> {
        let box = NIOLoopBoundBox<Result<T, Error>?>(nil, eventLoop: future.eventLoop)
        future.whenComplete { box.value = $0 }
        return box
    }

    /// How a held keyboard-interactive delegate callback finally answers.
    private enum LateAnswer: CaseIterable {
        case challenge
        case success
        case failure
        case promiseFailed

        func complete(_ promise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>) {
            switch self {
            case .challenge: promise.succeed(.challenge(KIFixtures.passwordChallenge))
            case .success: promise.succeed(.outcome(.success))
            case .failure: promise.succeed(.outcome(.failure))
            case .promiseFailed: promise.fail(KITestError.bang)
            }
        }
    }

    private func isAbandoned(_ result: Result<NIOSSHUserAuthenticationServerStepMessage, Error>?) -> Bool {
        if case .some(.success(.abandoned)) = result {
            return true
        }
        return false
    }

    func testServerDropsResultOfAbandonedKeyboardInteractiveRequest() throws {
        // A (alice, keyboard-interactive) is held by the delegate; B (bob) arrives; A answers late.
        for late in LateAnswer.allCases {
            for newRequestIsKeyboardInteractive in [true, false] {
                let context = "late \(late), B is \(newRequestIsKeyboardInteractive ? "keyboard-interactive" : "password")"
                let delegate = ControllableKeyboardInteractiveServerDelegate(
                    supportedAuthenticationMethods: [.password, .keyboardInteractive],
                    holdRequests: true,
                    holdResponses: true
                )
                var stateMachine = try self.makeServer(delegate)

                let a = self.box(try XCTUnwrap(try stateMachine.receiveUserAuthRequestStep(self.kiRequest("alice"))))
                XCTAssertEqual(stateMachine._serverPendingAnswersForTesting, 1, context)
                let bRequest = newRequestIsKeyboardInteractive ? self.kiRequest("bob") : self.passwordRequest("bob")
                let b = self.box(try XCTUnwrap(try stateMachine.receiveUserAuthRequestStep(bRequest)))
                // RFC 4252 §5.1: A is aborted and owes nothing any more; only B is pending.
                XCTAssertEqual(stateMachine._serverPendingAnswersForTesting, 1, "\(context): A's pending answer must be settled")

                late.complete(delegate.heldRequests[0].promise)
                self.loop.run()
                XCTAssertTrue(self.isAbandoned(a.value), "\(context): A must produce no message, got \(String(describing: a.value))")

                if newRequestIsKeyboardInteractive {
                    XCTAssertEqual(delegate.heldRequests.map { $0.username }, ["alice", "bob"], context)
                    delegate.heldRequests[1].promise.succeed(.challenge(KIFixtures.passwordChallenge))
                    self.loop.run()
                    guard case .some(.success(.infoRequest(let challenge))) = b.value else {
                        XCTFail("\(context): B must get its challenge, got \(String(describing: b.value))")
                        continue
                    }
                    XCTAssertNoThrow(try stateMachine.sendUserAuthInfoRequest(challenge), context)
                    XCTAssertEqual(stateMachine._serverPendingAnswersForTesting, 0, context)
                    let answer = self.box(
                        try XCTUnwrap(try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["x"])))
                    )
                    XCTAssertEqual(delegate.responseUsernames, ["bob"], "\(context): B stays bound to bob")
                    delegate.heldResponses[0].promise.succeed(.outcome(.failure))
                    self.loop.run()
                    XCTAssertNotNil(answer.value, context)
                } else {
                    guard case .some(.success(.response(.failure(let bFailure)))) = b.value else {
                        XCTFail("\(context): B must fail, got \(String(describing: b.value))")
                        continue
                    }
                    stateMachine.sendUserAuthFailure(bFailure)
                    XCTAssertEqual(stateMachine._serverPendingAnswersForTesting, 0, context)
                    // A's late answer left no outstanding challenge behind.
                    self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["x"])))
                    XCTAssertTrue(delegate.responseUsernames.isEmpty, context)
                }
            }
        }
    }

    func testServerDropsResultOfAbandonedKeyboardInteractiveResponse() throws {
        // A's challenge was answered; its INFO_RESPONSE is held by the delegate when B arrives.
        for late in LateAnswer.allCases {
            let delegate = ControllableKeyboardInteractiveServerDelegate(
                supportedAuthenticationMethods: [.password, .keyboardInteractive],
                holdRequests: false,
                holdResponses: true
            )
            var stateMachine = try self.makeServer(delegate)
            guard
                case .infoRequest(let challenge) = try self.serverStep(
                    try stateMachine.receiveUserAuthRequestStep(self.kiRequest("alice"))
                )
            else {
                XCTFail("late \(late): expected A's challenge")
                continue
            }
            try stateMachine.sendUserAuthInfoRequest(challenge)
            let a = self.box(try XCTUnwrap(try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["secret"]))))
            XCTAssertEqual(delegate.responseUsernames, ["alice"])
            XCTAssertEqual(stateMachine._serverPendingAnswersForTesting, 1)

            let b = self.box(try XCTUnwrap(try stateMachine.receiveUserAuthRequestStep(self.passwordRequest("bob"))))
            XCTAssertEqual(stateMachine._serverPendingAnswersForTesting, 1, "late \(late): A's pending answer must be settled")
            guard case .some(.success(.response(.failure(let bFailure)))) = b.value else {
                XCTFail("late \(late): B must fail")
                continue
            }
            stateMachine.sendUserAuthFailure(bFailure)
            XCTAssertEqual(stateMachine._serverPendingAnswersForTesting, 0)

            late.complete(delegate.heldResponses[0].promise)
            self.loop.run()
            XCTAssertTrue(self.isAbandoned(a.value), "late \(late): A must produce no message, got \(String(describing: a.value))")
            self.assertProtocolViolation(try stateMachine.receiveUserAuthInfoResponse(.init(responses: ["secret"])))
        }
    }

    func testServerStillReportsErrorOfCurrentKeyboardInteractiveCallback() throws {
        // Not aborted: a failed delegate promise still surfaces as an error, exactly as before.
        let delegate = ControllableKeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            holdRequests: true,
            holdResponses: true
        )
        var stateMachine = try self.makeServer(delegate)
        let a = self.box(try XCTUnwrap(try stateMachine.receiveUserAuthRequestStep(self.kiRequest("alice"))))
        delegate.heldRequests[0].promise.fail(KITestError.bang)
        self.loop.run()
        guard case .some(.failure(let error)) = a.value else {
            XCTFail("expected the delegate's error, got \(String(describing: a.value))")
            return
        }
        XCTAssertEqual(error as? KITestError, .bang)
    }

    private enum HeldCallback: CaseIterable {
        case initialChallenge
        case infoResponse
    }

    /// Over a real pair of connection state machines: A (keyboard-interactive) is held at `held`; the client then
    /// pipelines B (password, RFC 4252 §5); B succeeds or fails; only then does A answer, `late`.
    private func runAbandonedAttemptOverConnection(
        held: HeldCallback,
        newAttemptSucceeds: Bool,
        late: LateAnswer
    ) throws {
        let context = "held \(held), B \(newAttemptSucceeds ? "succeeds" : "fails"), A late \(late)"
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.keyboardInteractive(.init())), .hold],
            answer: KIFixtures.answerEveryPrompt(with: "secret")
        )
        let server = ControllableKeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: [.password, .keyboardInteractive],
            holdRequests: held == .initialChallenge,
            holdResponses: held == .infoResponse
        )
        server.plainOutcome = newAttemptSucceeds ? .success : .failure
        let pair = ConnectionPair(client: client, server: server, hostKey: self.hostKey, loop: self.loop)
        try pair.pump()
        let heldPromise = try XCTUnwrap(
            held == .initialChallenge ? server.heldRequests.first?.promise : server.heldResponses.first?.promise,
            context
        )

        // B: the client pipelines a password request while A is still being decided.
        pair.client._abandonInFlightUserAuthRequestForTesting()
        pair.toSendFromClient.value.append(
            SSHMultiMessage(.userAuthRequest(.init(username: "bob", service: "ssh-connection", method: .password("pw"))))
        )
        let sentBeforeB = pair.sentByServer.count
        try pair.pump()
        let sentForB = Array(pair.sentByServer[sentBeforeB...])
        if newAttemptSucceeds {
            XCTAssertEqual(sentForB, [.userAuthSuccess], "\(context): only B's SUCCESS goes out")
            XCTAssertTrue(pair.server.isActive, context)
            XCTAssertTrue(pair.client.isActive, context)
        } else {
            XCTAssertEqual(
                sentForB,
                [.userAuthFailure(.init(authentications: ["password", "keyboard-interactive"], partialSuccess: false))],
                "\(context): only B's FAILURE goes out — none for the aborted A"
            )
        }

        // A answers late: nothing goes out, nothing is reported, nothing is closed.
        let sentBeforeLate = pair.sentByServer.count
        late.complete(heldPromise)
        self.loop.run()
        XCTAssertTrue(pair.toSendFromServer.value.isEmpty, "\(context): A's late answer produced a message")
        try pair.pump()
        XCTAssertEqual(pair.sentByServer.count, sentBeforeLate, "\(context): A's late answer was written")
        XCTAssertEqual(pair.futureErrors.value, [], "\(context): A's late answer raised an error")
        XCTAssertFalse(pair.server.disconnected, context)

        if newAttemptSucceeds {
            // B's connection still carries traffic.
            let allocator = ByteBufferAllocator()
            var bytes = allocator.buffer(capacity: 256)
            let open = SSHMessage.channelOpen(
                .init(type: .session, senderChannel: 1, initialWindowSize: 1 << 20, maximumPacketSize: 1 << 15)
            )
            try pair.client.processOutboundMessage(open, buffer: &bytes, allocator: allocator, loop: self.loop)
            pair.server.bufferInboundData(&bytes)
            guard case .some(.forwardToMultiplexer(let forwarded)) = try pair.server.processInboundMessage(
                allocator: allocator,
                loop: self.loop
            ) else {
                XCTFail("\(context): B's connection no longer carries channel traffic")
                return
            }
            XCTAssertEqual(forwarded, open, context)
        } else {
            // The client is asking its delegate what to do after B's FAILURE; let it give up.
            client.heldOffer?.succeed(nil)
            self.loop.run()
        }
    }

    func testAbandonedKeyboardInteractiveAttemptLeavesSucceededNewAttemptAlone() throws {
        for held in HeldCallback.allCases {
            for late in LateAnswer.allCases {
                try self.runAbandonedAttemptOverConnection(held: held, newAttemptSucceeds: true, late: late)
            }
        }
    }

    func testAbandonedKeyboardInteractiveAttemptSendsNothingWhileNewAttemptIsAuthenticating() throws {
        for held in HeldCallback.allCases {
            for late in LateAnswer.allCases {
                try self.runAbandonedAttemptOverConnection(held: held, newAttemptSucceeds: false, late: late)
            }
        }
    }

    func testClientRejectsOutcomeWhileItsHeldAnswerIsPending() throws {
        for outcome in ["success", "failure"] {
            let delegate = ScriptedKeyboardInteractiveClientDelegate(
                steps: [.offer(.none), .offer(.keyboardInteractive(.init()))],
                answer: KIFixtures.answerEveryPrompt(with: "secret")
            )
            delegate.holdChallenges = true
            var stateMachine = try self.clientWithKeyboardInteractiveInFlight(delegate)
            let answer = self.box(try stateMachine.receiveUserAuthInfoRequest(KIFixtures.passwordChallengeMessage))
            self.loop.run()
            XCTAssertEqual(delegate.heldChallenges.count, 1)
            XCTAssertNil(answer.value, "NIOSSH must not complete the delegate's promise itself")

            if outcome == "success" {
                self.assertProtocolViolation(try stateMachine.receiveUserAuthSuccess())
            } else {
                self.assertProtocolViolation(
                    try stateMachine.receiveUserAuthFailure(
                        .init(authentications: ["keyboard-interactive"], partialSuccess: false)
                    )
                )
            }

            // The late answer only completes its own future.
            delegate.heldChallenges[0].succeed(.init(responses: ["secret"]))
            self.loop.run()
            guard case .some(.success(let response)) = answer.value else {
                XCTFail("\(outcome): late answer did not complete the future")
                continue
            }
            XCTAssertEqual(response.responses, ["secret"])
        }
    }

    // MARK: - F2 (STATIC-01): held callback, then teardown, then a late answer

    private enum HoldPoint: CaseIterable {
        case clientChallenge
        case serverInitialChallenge
        case serverResponse
    }

    private func runHeldThenTeardown(_ point: HoldPoint, lateSucceeds: Bool) throws {
        let label = "\(point) late \(lateSucceeds ? "success" : "failure")"
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "secret")
        )
        client.holdChallenges = point == .clientChallenge
        let server = ControllableKeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            holdRequests: point == .serverInitialChallenge,
            holdResponses: point == .serverResponse
        )
        let pair = BackToBackEmbeddedChannel()
        var harness = TestHarness()
        harness.clientAuthDelegate = client
        harness.serverAuthDelegate = server
        try pair.configureWithHarness(harness)
        try pair.activate()
        try pair.interactInMemory()

        // Exactly one callback is held, and NIOSSH has not completed it.
        let side: EmbeddedChannel
        let completed: NIOLoopBoundBox<String?>
        let completeLate: () -> Void
        switch point {
        case .clientChallenge:
            XCTAssertEqual(client.heldChallenges.count, 1, label)
            let promise = try XCTUnwrap(client.heldChallenges.first)
            side = pair.client
            completed = NIOLoopBoundBox(nil, eventLoop: pair.client.eventLoop)
            promise.futureResult.whenComplete { completed.value = "\($0)" }
            completeLate = {
                if lateSucceeds {
                    promise.succeed(.init(responses: ["secret"]))
                } else {
                    promise.fail(KITestError.bang)
                }
            }
        case .serverInitialChallenge, .serverResponse:
            let held = point == .serverInitialChallenge ? server.heldRequests : server.heldResponses
            XCTAssertEqual(held.count, 1, label)
            let promise = try XCTUnwrap(held.first).promise
            side = pair.server
            completed = NIOLoopBoundBox(nil, eventLoop: pair.server.eventLoop)
            promise.futureResult.whenComplete { completed.value = "\($0)" }
            completeLate = {
                if lateSucceeds {
                    promise.succeed(
                        point == .serverInitialChallenge ? .challenge(KIFixtures.passwordChallenge) : .outcome(.success)
                    )
                } else {
                    promise.fail(KITestError.bang)
                }
            }
        }
        XCTAssertNil(completed.value, "\(label): NIOSSH completed the delegate's promise")

        // Teardown of the side whose callback is held.
        side.close(promise: nil)
        pair.run()
        XCTAssertNil(completed.value, "\(label): teardown completed the delegate's promise")

        // The late answer: completes once, writes nothing, raises nothing, crashes nothing.
        completeLate()
        pair.run()
        XCTAssertNotNil(completed.value, label)
        XCTAssertNil(try side.readOutbound(as: IOData.self), "\(label): bytes written after teardown")
        XCTAssertNoThrow(try side.throwIfErrorCaught(), label)

        try pair.finish()
    }

    func testHeldClientChallengeAnswerAfterTeardownGoesNowhere() throws {
        try self.runHeldThenTeardown(.clientChallenge, lateSucceeds: true)
        try self.runHeldThenTeardown(.clientChallenge, lateSucceeds: false)
    }

    func testHeldServerInitialChallengeAfterTeardownGoesNowhere() throws {
        try self.runHeldThenTeardown(.serverInitialChallenge, lateSucceeds: true)
        try self.runHeldThenTeardown(.serverInitialChallenge, lateSucceeds: false)
    }

    func testHeldServerResponseStepAfterTeardownGoesNowhere() throws {
        try self.runHeldThenTeardown(.serverResponse, lateSucceeds: true)
        try self.runHeldThenTeardown(.serverResponse, lateSucceeds: false)
    }

    // MARK: - F3 (STATIC-01): the server's method names verbatim

    func testClientDelegateReceivesServerMethodNamesVerbatim() throws {
        let cases: [([Substring], NIOSSHAvailableUserAuthenticationMethods)] = [
            ([], []),
            (["gssapi-with-mic"], []),
            (["publickey", "gssapi-with-mic", "keyboard-interactive"], [.publicKey, .keyboardInteractive]),
        ]
        for (names, methods) in cases {
            for partialSuccess in [false, true] {
                let delegate = ScriptedKeyboardInteractiveClientDelegate(
                    steps: [.offer(.none), .noMoreOffers],
                    answer: KIFixtures.answerEveryPrompt(with: "x")
                )
                var stateMachine = self.makeClient(delegate)
                let probe = try XCTUnwrap(try self.clientAfterServiceAccept(&stateMachine))
                stateMachine.sendUserAuthRequest(probe)
                let next = try XCTUnwrap(
                    try stateMachine.receiveUserAuthFailure(.init(authentications: names, partialSuccess: partialSuccess))
                )
                XCTAssertNil(try XCTUnwrap(self.resolve(next)).get())
                // First call: nothing listed yet; second call: exactly what the server sent, unknown names included
                // (the same for a partial success, which lists the remaining methods the same way).
                XCTAssertEqual(delegate.serverNamesSeen, [[], names.map { String($0) }], "partialSuccess=\(partialSuccess)")
                XCTAssertEqual(delegate.availableMethodsSeen, [.all, methods], "partialSuccess=\(partialSuccess)")
            }
        }
    }

    // MARK: - F4 (STATIC-01): parser context is restored

    func testParserContextIsRestoredAfterKeyboardInteractiveFailure() throws {
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.keyboardInteractive(.init())), .hold],
            answer: KIFixtures.answerEveryPrompt(with: "wrong")
        )
        let server = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: [.keyboardInteractive, .publicKey],
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        let pair = ConnectionPair(client: client, server: server, hostKey: self.hostKey, loop: self.loop)
        try pair.pump()

        // The KI attempt ran and failed; the delegate is holding the next offer.
        XCTAssertEqual(client.challengesSeen.count, 1)
        XCTAssertEqual(server.responsesSeen.map { $0.responses }, [["wrong"]])
        XCTAssertNotNil(client.heldOffer)
        XCTAssertEqual(pair.client._userAuthMessageContextForTesting, .default, "FAILURE must restore PK_OK parsing")

        // Next request is publickey: 60 must still mean PK_OK.
        client.heldOffer?.succeed(
            .init(username: "foo", serviceName: "", offer: .privateKey(.init(privateKey: NIOSSHPrivateKey(ed25519Key: .init()))))
        )
        try pair.pump()
        XCTAssertEqual(server.plainRequests.count, 1, "the publickey request reached the server")
        XCTAssertEqual(pair.client._userAuthMessageContextForTesting, .default)
    }

    func testParserContextIsRestoredAfterKeyboardInteractiveSuccess() throws {
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "secret")
        )
        let server = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        let pair = ConnectionPair(client: client, server: server, hostKey: self.hostKey, loop: self.loop)
        try pair.pump()

        XCTAssertTrue(pair.client.isActive)
        XCTAssertEqual(client.challengesSeen.count, 1)
        XCTAssertEqual(pair.client._userAuthMessageContextForTesting, .default, "SUCCESS must restore PK_OK parsing")
    }

    func testParserContextIsDroppedWithTheStateOnDisconnect() throws {
        let client = ScriptedKeyboardInteractiveClientDelegate(
            steps: [.offer(.keyboardInteractive(.init()))],
            answer: KIFixtures.answerEveryPrompt(with: "secret")
        )
        client.holdChallenges = true
        let server = KeyboardInteractiveServerDelegate(
            supportedAuthenticationMethods: .keyboardInteractive,
            challenges: [KIFixtures.passwordChallenge],
            expectedResponses: [["secret"]]
        )
        let pair = ConnectionPair(client: client, server: server, hostKey: self.hostKey, loop: self.loop)
        try pair.pump()

        // Challenge received and held: the client is reading 60 as INFO_REQUEST.
        XCTAssertEqual(client.heldChallenges.count, 1)
        XCTAssertEqual(pair.client._userAuthMessageContextForTesting, .keyboardInteractive)

        pair.toSendFromServer.value.append(SSHMultiMessage(.disconnect(.init(reason: 11, description: "bye", tag: ""))))
        try pair.pump()
        XCTAssertTrue(pair.client.disconnected)
        XCTAssertNil(pair.client._userAuthMessageContextForTesting, "no parser (and no context) survives a disconnect")

        // Complete the held promise; its INFO_RESPONSE is never sent (the pair is not pumped again).
        client.heldChallenges[0].succeed(.init(responses: ["secret"]))
        self.loop.run()
    }
}
