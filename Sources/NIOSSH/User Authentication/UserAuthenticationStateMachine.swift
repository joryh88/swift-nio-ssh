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
// Modified by the Brizmo project (2026-11-01): keyboard-interactive user authentication (RFC 4256)
// for both roles. See BRIZMO-PATCH.md.
//
//===----------------------------------------------------------------------===//

import NIOConcurrencyHelpers
import NIOCore

struct UserAuthenticationStateMachine {
    private var state: State
    private var delegate: UserAuthDelegate

    /// Brizmo patch (RFC 4256): progress of a keyboard-interactive exchange, orthogonal to `state`.
    private var keyboardInteractive: KeyboardInteractiveState

    /// Brizmo patch (server only): the keyboard-interactive attempt that is still current — the serial of
    /// the USERAUTH_REQUEST that started it and its user name. Cleared by every new USERAUTH_REQUEST.
    private var serverKeyboardInteractiveAttempt: (serial: UInt64, username: String)?

    /// Brizmo patch (server only): serial of the latest USERAUTH_REQUEST received, and which keyboard-interactive
    /// attempt (if any) still has a delegate callback out. Shared with the futures of those callbacks. RFC 4252
    /// §5.1: a new request aborts the previous method, and "A SSH_MSG_USERAUTH_FAILURE message MUST NOT be sent
    /// for an aborted method" — so an abandoned attempt's pending answer is settled when the new request arrives
    /// (nothing is sent), and its late result or error is dropped (see `keyboardInteractiveCallbackIsCurrent`).
    private let serverKeyboardInteractiveClock: NIOLockedValueBox<KeyboardInteractiveClock>
    private let loop: EventLoop
    private var sessionID: ByteBuffer

    /// The maximum number of `SSH_MSG_USERAUTH_REQUEST` messages this server will process before
    /// disconnecting. Taken from `SSHServerConfiguration`; `.max` for clients, which never enforce it.
    private let maxAuthAttempts: Int

    init(role: SSHConnectionRole, loop: EventLoop, sessionID: ByteBuffer) {
        self.state = .idle
        self.delegate = UserAuthDelegate(role: role)
        self.loop = loop
        self.sessionID = sessionID
        self.keyboardInteractive = .inactive
        self.serverKeyboardInteractiveAttempt = nil
        self.serverKeyboardInteractiveClock = NIOLockedValueBox(KeyboardInteractiveClock())
        switch role {
        case .server(let configuration):
            self.maxAuthAttempts = configuration.maxAuthAttempts ?? Constants.defaultMaxAuthAttempts
        case .client:
            self.maxAuthAttempts = .max
        }
    }

    fileprivate static let serviceName: String = "ssh-userauth"

    fileprivate static let nextServiceName: String = "ssh-connection"

    private static let tooManyTriesDisconnect = SSHMessage.DisconnectMessage(
        reason: 11,  // SSH_DISCONNECT_BY_APPLICATION
        description: "Too many authentication failures",
        tag: ""
    )
}

extension UserAuthenticationStateMachine {
    fileprivate enum State {
        /// In this state, we have not received any user auth messages yet
        case idle
        case awaitingServiceAcceptance
        case awaitingNextRequest(attempts: Int)
        case awaitingResponses(attempts: Int, pending: Int)
        case authenticationSucceeded
        case authenticationFailed
    }

    /// Brizmo patch (RFC 4256). Tracked next to `State` instead of inside it so that every upstream
    /// transition stays as it was.
    fileprivate enum KeyboardInteractiveState {
        /// No keyboard-interactive exchange is waiting on anything.
        case inactive

        /// Client: our in-flight USERAUTH_REQUEST is keyboard-interactive and we owe nothing. The server's next
        /// word is INFO_REQUEST, SUCCESS or FAILURE.
        case clientAwaitingServer

        /// Client: an INFO_REQUEST with `promptCount` prompts is with the delegate; our INFO_RESPONSE has not
        /// been written yet.
        case clientAnswering(promptCount: Int)

        /// Server: we sent `username` an INFO_REQUEST with `promptCount` prompts for the attempt started by
        /// USERAUTH_REQUEST number `serial`, and wait for INFO_RESPONSE.
        case serverAwaitingResponse(username: String, promptCount: Int, serial: UInt64)
    }
}

extension UserAuthenticationStateMachine {
    fileprivate static let protocolName = "userauth"
}

// MARK: Receiving Messages

extension UserAuthenticationStateMachine {
    /// A ServiceRequest message was received from the remote peer.
    mutating func receiveServiceRequest(
        _ message: SSHMessage.ServiceRequestMessage
    ) throws -> SSHMessage.ServiceAcceptMessage? {
        switch (self.delegate, self.state) {
        case (.server, .idle):
            guard message.service == Self.serviceName else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "unexpected service request: \(message)"
                )
            }

            self.state = .awaitingServiceAcceptance
            return .init(service: Self.serviceName)

        case (.server, .awaitingServiceAcceptance),
            (.server, .awaitingNextRequest),
            (.server, .awaitingResponses):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unexpected state for service request: \(message)"
            )

        case (.server, .authenticationSucceeded):
            // We ignore messages after authentication succeeded.
            return nil

        case (.server, .authenticationFailed):
            // We have already emitted a disconnect; ignore anything still in flight.
            return nil

        case (.client, _):
            // Clients may never receive user service request messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent service request: \(message)"
            )
        }
    }

    /// A ServiceAccept message was received from the remote peer.
    mutating func receiveServiceAccept(
        _ message: SSHMessage.ServiceAcceptMessage
    ) throws -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?>? {
        switch (self.delegate, self.state) {
        case (.client(let delegate), .awaitingServiceAcceptance):
            guard message.service == Self.serviceName else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "unexpected service accept: \(message)"
                )
            }

            // Cool, we can begin the auth dance.
            self.state = .awaitingNextRequest(attempts: 0)
            // Brizmo patch: no server list exists yet, so no server method names either.
            return self.requestNextAuthRequest(methods: .all, serverOfferedMethodNames: [], delegate: delegate)
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            return nil
        case (.client, .idle):
            // Server sent a service accept but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited service accept message: \(message)"
            )
        case (.client, .awaitingNextRequest),
            (.client, .awaitingResponses),
            (.client, .authenticationFailed):
            // In these states we aren't expecting a service accept message
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited service accept message: \(message)"
            )
        case (.server, _):
            // Servers may never receive user auth success messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth success"
            )
        }
    }

    /// A UserAuthRequest message was received from the remote peer.
    ///
    /// Brizmo patch: upstream entry point, kept with its signature and behaviour for every existing method.
    /// The connection state machine now calls ``receiveUserAuthRequestStep(_:)``, because a keyboard-interactive
    /// request may be answered with an INFO_REQUEST, which ``NIOSSHUserAuthenticationResponseMessage`` cannot
    /// express; through this entry point such an answer fails the future with a protocol violation.
    mutating func receiveUserAuthRequest(
        _ message: SSHMessage.UserAuthRequestMessage
    ) throws -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage>? {
        let protocolName = Self.protocolName
        return try self.receiveUserAuthRequestStep(message).map { future in
            future.flatMapThrowing { step in
                switch step {
                case .response(let response):
                    return response
                case .infoRequest, .abandoned:
                    throw NIOSSHError.protocolViolation(
                        protocolName: protocolName,
                        violation: "keyboard-interactive step has no plain user auth response form"
                    )
                }
            }
        }
    }

    /// Brizmo patch: a UserAuthRequest message was received from the remote peer (server role). Same state
    /// transitions as upstream `receiveUserAuthRequest`; the answer may additionally be an INFO_REQUEST.
    mutating func receiveUserAuthRequestStep(
        _ message: SSHMessage.UserAuthRequestMessage
    ) throws -> EventLoopFuture<NIOSSHUserAuthenticationServerStepMessage>? {
        guard message.service == Self.nextServiceName else {
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "requested unsupported service: \(message.service)"
            )
        }

        switch (self.delegate, self.state) {
        case (.server(let delegate), .awaitingNextRequest), (.server(let delegate), .awaitingResponses):
            // Brizmo patch: may settle the pending answer of an abandoned keyboard-interactive attempt, so the
            // attempt/pending counts are read only afterwards. Non-keyboard-interactive bookkeeping is unchanged.
            let serial = self.beginServerRequest()
            let (attempts, pending): (Int, Int)
            switch self.state {
            case .awaitingNextRequest(let current):
                (attempts, pending) = (current, 0)
            case .awaitingResponses(let current, let currentPending):
                (attempts, pending) = (current, currentPending)
            case .idle, .awaitingServiceAcceptance, .authenticationSucceeded, .authenticationFailed:
                preconditionFailure("beginServerRequest left the request-accepting states: \(self.state)")
            }
            guard attempts < self.maxAuthAttempts else {
                self.state = .authenticationFailed
                return self.loop.makeSucceededFuture(.response(.disconnect(Self.tooManyTriesDisconnect)))
            }
            self.state = .awaitingResponses(attempts: attempts + 1, pending: pending + 1)
            return self.nextAuthStep(request: message, serial: serial, delegate: delegate)

        case (.server, .idle), (.server, .awaitingServiceAcceptance):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "user auth request before service accepted"
            )

        case (.server, .authenticationSucceeded):
            // We ignore messages after authentication succeeded.
            return nil

        case (.server, .authenticationFailed):
            // We have already emitted a disconnect; ignore anything still in flight.
            return nil

        case (.client, _):
            // Clients may never receive user auth request messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent user auth request"
            )
        }
    }

    /// We've received a user auth success message.
    ///
    /// If this method completes without throwing, user auth has completed.
    mutating func receiveUserAuthSuccess() throws {
        switch (self.delegate, self.state) {
        case (.client, .awaitingResponses):
            // Brizmo patch (RFC 4256 §3.4): the server decides only after our INFO_RESPONSE.
            try self.checkNoUnansweredKeyboardInteractiveChallenge(received: "auth success")
            self.keyboardInteractive = .inactive
            // Great, we got a response, and it's a success! Disregard all future responses
            self.state = .authenticationSucceeded
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            break
        case (.client, .idle), (.client, .awaitingServiceAcceptance):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited auth success message"
            )
        case (.client, .awaitingNextRequest), (.client, .authenticationFailed):
            // In these states we believe we received all our auth responses, so this is wrong.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited auth success message"
            )
        case (.server, _):
            // Servers may never receive user auth success messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth success"
            )
        }
    }

    mutating func receiveUserAuthFailure(
        _ message: SSHMessage.UserAuthFailureMessage
    ) throws -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?>? {
        switch (self.delegate, self.state) {
        case (.client(let delegate), .awaitingResponses(let attempts, let responseCount)):
            // Brizmo patch (RFC 4256 §3.4): the server decides only after our INFO_RESPONSE.
            try self.checkNoUnansweredKeyboardInteractiveChallenge(received: "auth failure")
            self.keyboardInteractive = .inactive
            // Ok, the server didn't like that much. Let's try another one.
            self.state = .awaitingNextRequest(attempts: attempts)
            precondition(responseCount == 1, "We don't support parallel authentication attempts yet!")
            // Brizmo patch: also pass the server's own method names, unknown ones included.
            return self.requestNextAuthRequest(
                methods: .init(message),
                serverOfferedMethodNames: message.authentications.map { String($0) },
                delegate: delegate
            )
        case (.client, .authenticationSucceeded):
            // We should ignore all further auth messages in this state.
            return nil
        case (.client, .idle), (.client, .awaitingServiceAcceptance):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent user auth failure unprompted"
            )
        case (.client, .awaitingNextRequest), (.client, .authenticationFailed):
            // In these states we believe we received all our auth responses, so this is wrong.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unsolicited auth failure message"
            )
        case (.server, _):
            // Servers may never receive user auth failure messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth failure"
            )
        }
    }

    /// Brizmo patch (RFC 4256 §3.2, client role): the server sent a keyboard-interactive challenge.
    ///
    /// Legal only while our in-flight request is keyboard-interactive and no earlier challenge is still
    /// unanswered; anything else (including while a publickey request is in flight, where 60 would be PK_OK,
    /// which this client still does not handle) is a protocol violation. The returned future carries our
    /// INFO_RESPONSE; it fails, and nothing is sent, if the delegate fails or answers with a number of
    /// responses different from the number of prompts.
    mutating func receiveUserAuthInfoRequest(
        _ message: SSHMessage.UserAuthInfoRequestMessage
    ) throws -> EventLoopFuture<SSHMessage.UserAuthInfoResponseMessage> {
        switch (self.delegate, self.state) {
        case (.client(let delegate), .awaitingResponses):
            guard case .clientAwaitingServer = self.keyboardInteractive else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "keyboard-interactive info request without an unanswered keyboard-interactive request"
                )
            }

            let promptCount = message.prompts.count
            self.keyboardInteractive = .clientAnswering(promptCount: promptCount)
            let promise = self.loop.makePromise(of: NIOSSHKeyboardInteractiveResponse.self)
            delegate.keyboardInteractiveChallengeReceived(
                NIOSSHKeyboardInteractiveChallenge(message),
                responsePromise: promise
            )

            let protocolName = Self.protocolName
            return promise.futureResult.flatMapThrowing { response in
                // RFC 4256 §3.4: num-responses MUST equal num-prompts. Never put any other count on the wire.
                guard response.responses.count == promptCount else {
                    throw NIOSSHError.protocolViolation(
                        protocolName: protocolName,
                        violation:
                            "keyboard-interactive response count \(response.responses.count) does not match prompt count \(promptCount)"
                    )
                }
                return SSHMessage.UserAuthInfoResponseMessage(responses: response.responses)
            }

        case (.client, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "unexpected keyboard-interactive info request in state \(self.state)"
            )

        case (.server, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent keyboard-interactive info request"
            )
        }
    }

    /// Brizmo patch (RFC 4256 §3.4, server role): the client answered a keyboard-interactive challenge.
    ///
    /// Legal only while a challenge we sent is unanswered. The response continues the same attempt: it is
    /// not a USERAUTH_REQUEST and does not count toward `maxAuthAttempts`. A number of responses different
    /// from the number of prompts is answered with FAILURE (the connection stays up).
    mutating func receiveUserAuthInfoResponse(
        _ message: SSHMessage.UserAuthInfoResponseMessage
    ) throws -> EventLoopFuture<NIOSSHUserAuthenticationServerStepMessage>? {
        switch (self.delegate, self.state) {
        case (.server(let delegate), .awaitingNextRequest(let attempts)):
            return try self.nextKeyboardInteractiveStep(message, delegate: delegate, attempts: attempts, pending: 0)

        case (.server(let delegate), .awaitingResponses(let attempts, let pending)):
            return try self.nextKeyboardInteractiveStep(
                message,
                delegate: delegate,
                attempts: attempts,
                pending: pending
            )

        case (.server, .idle), (.server, .awaitingServiceAcceptance):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "keyboard-interactive info response before any auth request"
            )

        case (.server, .authenticationSucceeded), (.server, .authenticationFailed):
            // Same as other user auth messages in these states: ignored.
            return nil

        case (.client, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent keyboard-interactive info response"
            )
        }
    }

    private mutating func nextKeyboardInteractiveStep(
        _ message: SSHMessage.UserAuthInfoResponseMessage,
        delegate: NIOSSHServerUserAuthenticationDelegate,
        attempts: Int,
        pending: Int
    ) throws -> EventLoopFuture<NIOSSHUserAuthenticationServerStepMessage> {
        guard case .serverAwaitingResponse(let username, let promptCount, let serial) = self.keyboardInteractive else {
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "keyboard-interactive info response without an unanswered challenge"
            )
        }

        self.keyboardInteractive = .inactive
        // Not a new request: `attempts` is unchanged; one more answer is now owed to the client.
        self.state = .awaitingResponses(attempts: attempts, pending: pending + 1)

        let supportedMethods = delegate.supportedAuthenticationMethods
        guard message.responses.count == promptCount else {
            return self.loop.makeSucceededFuture(
                .response(.failure(.init(authentications: supportedMethods.strings, partialSuccess: false)))
            )
        }

        let promise = self.loop.makePromise(of: NIOSSHKeyboardInteractiveServerStep.self)
        self.serverKeyboardInteractiveClock.withLockedValue { $0.callbackOutstanding = serial }
        delegate.keyboardInteractiveResponseReceived(
            username: username,
            response: NIOSSHKeyboardInteractiveResponse(responses: message.responses),
            responsePromise: promise
        )
        return keyboardInteractiveStepFuture(
            promise.futureResult,
            serial: serial,
            clock: self.serverKeyboardInteractiveClock,
            supportedMethods: supportedMethods
        )
    }

    /// Brizmo patch (server role): bookkeeping for every received USERAUTH_REQUEST, before anything else.
    /// The keyboard-interactive attempt in progress, if any, is aborted (RFC 4252 §5.1): an unanswered challenge
    /// is forgotten, and if its delegate callback is still out, the pending answer it accounts for is settled
    /// here — no message is ever sent for it ("A SSH_MSG_USERAUTH_FAILURE message MUST NOT be sent for an
    /// aborted method"); the callback's late result or error is dropped when it arrives.
    private mutating func beginServerRequest() -> UInt64 {
        self.keyboardInteractive = .inactive
        self.serverKeyboardInteractiveAttempt = nil
        let (serial, abandonedCallback) = self.serverKeyboardInteractiveClock.withLockedValue {
            clock -> (UInt64, Bool) in
            let abandoned = clock.callbackOutstanding != nil
            clock.callbackOutstanding = nil
            clock.serial &+= 1
            return (clock.serial, abandoned)
        }
        if abandonedCallback, case .awaitingResponses(let attempts, let pending) = self.state {
            self.state =
                pending > 1
                ? .awaitingResponses(attempts: attempts, pending: pending - 1)
                : .awaitingNextRequest(attempts: attempts)
        }
        return serial
    }

    /// Brizmo patch, testing only: answers the server still owes (`nil` outside the request-accepting states).
    internal var _serverPendingAnswersForTesting: Int? {
        switch (self.delegate, self.state) {
        case (.server, .awaitingNextRequest):
            return 0
        case (.server, .awaitingResponses(_, let pending)):
            return pending
        default:
            return nil
        }
    }

    /// Brizmo patch, testing only: lets a client send its next USERAUTH_REQUEST while the previous one is still
    /// in flight, as RFC 4252 §5 permits a client to do. NIOSSH's own client never does this; tests use it to
    /// drive the server's abandoned-attempt handling over a real connection.
    internal mutating func _abandonInFlightRequestForTesting() {
        if case (.client, .awaitingResponses(let attempts, _)) = (self.delegate, self.state) {
            self.state = .awaitingNextRequest(attempts: attempts)
            self.keyboardInteractive = .inactive
        }
    }

    private func checkNoUnansweredKeyboardInteractiveChallenge(received what: String) throws {
        if case .clientAnswering = self.keyboardInteractive {
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "\(what) while our keyboard-interactive response is still outstanding"
            )
        }
    }

    mutating func receiveUserAuthBanner(_: SSHMessage.UserAuthBannerMessage) throws {
        switch (self.delegate, self.state) {
        case (.client, .idle), (.client, .authenticationSucceeded):
            // Server sent a user auth success but we didn't ask them to!
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "server sent user auth banner at the wrong time"
            )
        case (.server, _):
            // Servers may never receive user auth banner messages.
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "client sent user auth banner"
            )
        default:
            // In all other instances, receiving user auth banner is legal and must be dealt with by client
            return
        }
    }
}

// MARK: Sending Messages

extension UserAuthenticationStateMachine {
    mutating func sendServiceRequest(_ message: SSHMessage.ServiceRequestMessage) {
        switch (self.delegate, self.state) {
        case (.client, .idle):
            precondition(message.service == Self.serviceName)
            self.state = .awaitingServiceAcceptance
        case (.client, .awaitingServiceAcceptance):
            preconditionFailure("Duplicate service request")
        case (.client, .awaitingNextRequest),
            (.client, .awaitingResponses),
            (.client, .authenticationSucceeded),
            (.client, .authenticationFailed):
            preconditionFailure("May not send service request in \(self.state)")
        case (.server, _):
            preconditionFailure("Servers may not send service requests")
        }
    }

    mutating func sendServiceAccept(_ message: SSHMessage.ServiceAcceptMessage) {
        switch (self.delegate, self.state) {
        case (.server, .awaitingServiceAcceptance):
            precondition(message.service == Self.serviceName)
            self.state = .awaitingNextRequest(attempts: 0)
        case (.server, .idle):
            preconditionFailure("Cannot accept a service that hasn't been requested")
        case (.server, .awaitingNextRequest),
            (.server, .awaitingResponses),
            (.server, .authenticationSucceeded),
            (.server, .authenticationFailed):
            preconditionFailure("May not send service request in \(self.state)")
        case (.client, _):
            preconditionFailure("Clients may not send service acceptance")
        }
    }

    mutating func sendUserAuthRequest(_ message: SSHMessage.UserAuthRequestMessage) {
        switch (self.delegate, self.state) {
        case (.client, .awaitingNextRequest(let attempts)):
            self.state = .awaitingResponses(attempts: attempts, pending: 1)
            // Brizmo patch (RFC 4256): remember whether the request in flight is keyboard-interactive.
            if case .keyboardInteractive = message.method {
                self.keyboardInteractive = .clientAwaitingServer
            } else {
                self.keyboardInteractive = .inactive
            }
        case (.client, .idle),
            (.client, .awaitingServiceAcceptance):
            preconditionFailure("Sent an auth request without asking us first")
        case (.client, .awaitingResponses):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure(
                "Attempted to send a user auth request while we were waiting for a response to the last one."
            )
        case (.client, .authenticationSucceeded):
            preconditionFailure("Attempted to send a user auth request after auth succeeded")
        case (.client, .authenticationFailed):
            preconditionFailure("Attempted to send a user auth request after auth failed")
        case (.server, _):
            // Servers may never send user auth request messages.
            preconditionFailure("Servers may not authenticate")
        }
    }

    mutating func sendUserAuthPKOK(_: SSHMessage.UserAuthPKOKMessage) {
        switch (self.delegate, self.state) {
        case (.server, .idle),
            (.server, .awaitingServiceAcceptance):
            preconditionFailure("Server sent an auth response prior to receiving an auth request")
        case (.server, .awaitingNextRequest):
            preconditionFailure("Too many auth responses sent")
        case (.server, .awaitingResponses(let attempts, let responseCount)):
            if responseCount > 1 {
                self.state = .awaitingResponses(attempts: attempts, pending: responseCount - 1)
            } else {
                self.state = .awaitingNextRequest(attempts: attempts)
            }
        case (.server, .authenticationSucceeded):
            preconditionFailure("Authentication already succeeded, further messages are unnecessary.")
        case (.server, .authenticationFailed):
            preconditionFailure("Servers can never enter authenticationFailed")
        case (.client, _):
            preconditionFailure("Clients never send auth responses")
        }
    }

    /// Brizmo patch (RFC 4256 §3.2, server role): we are sending a keyboard-interactive challenge.
    ///
    /// Like PK_OK it answers the request (or INFO_RESPONSE) being processed; the attempt itself continues
    /// with the client's INFO_RESPONSE.
    mutating func sendUserAuthInfoRequest(_ message: SSHMessage.UserAuthInfoRequestMessage) throws {
        switch (self.delegate, self.state) {
        case (.server, .awaitingResponses(let attempts, let responseCount)):
            // Only the current attempt can challenge: results of an aborted attempt became `.abandoned` (no message).
            guard let attempt = self.serverKeyboardInteractiveAttempt,
                attempt.serial == self.serverKeyboardInteractiveClock.withLockedValue({ $0.serial })
            else {
                throw NIOSSHError.protocolViolation(
                    protocolName: Self.protocolName,
                    violation: "keyboard-interactive challenge without a current keyboard-interactive request"
                )
            }
            if responseCount > 1 {
                self.state = .awaitingResponses(attempts: attempts, pending: responseCount - 1)
            } else {
                self.state = .awaitingNextRequest(attempts: attempts)
            }
            self.keyboardInteractive = .serverAwaitingResponse(
                username: attempt.username,
                promptCount: message.prompts.count,
                serial: attempt.serial
            )

        case (.server, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "may not send a keyboard-interactive challenge in state \(self.state)"
            )

        case (.client, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "clients never send keyboard-interactive challenges"
            )
        }
    }

    /// Brizmo patch (RFC 4256 §3.4, client role): we are sending our answer to the unanswered challenge.
    mutating func sendUserAuthInfoResponse(_: SSHMessage.UserAuthInfoResponseMessage) throws {
        switch (self.delegate, self.state, self.keyboardInteractive) {
        case (.client, .awaitingResponses, .clientAnswering):
            self.keyboardInteractive = .clientAwaitingServer

        case (.client, _, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "keyboard-interactive info response without an unanswered challenge"
            )

        case (.server, _, _):
            throw NIOSSHError.protocolViolation(
                protocolName: Self.protocolName,
                violation: "servers never send keyboard-interactive info responses"
            )
        }
    }

    mutating func sendUserAuthSuccess() {
        self.sendUserAuthResponseMessage(success: true)
    }

    mutating func sendUserAuthFailure(_: SSHMessage.UserAuthFailureMessage) {
        self.sendUserAuthResponseMessage(success: false)
    }

    mutating func sendUserAuthBanner(_: SSHMessage.UserAuthBannerMessage) {
        // Relevant passage from RFC 4252:
        //
        // The SSH server may send an SSH_MSG_USERAUTH_BANNER message at any
        // time after this authentication protocol starts and before
        // authentication is successful.  This message contains text to be
        // displayed to the client user before authentication is attempted.  The
        // format is as follows:
        switch (self.delegate, self.state) {
        case (.server, .idle):
            preconditionFailure("Banner sent before authentication protocol start")
        case (.server, .authenticationSucceeded):
            preconditionFailure("Banner sent after authentication suceeded")
        case (.server, _):
            break
        case (.client, _):
            preconditionFailure("Clients never send auth responses")
        }
    }

    private mutating func sendUserAuthResponseMessage(success: Bool) {
        switch (self.delegate, self.state) {
        case (.server, .idle),
            (.server, .awaitingServiceAcceptance):
            preconditionFailure("Server sent an auth response prior to receiving an auth request")
        case (.server, .awaitingNextRequest):
            preconditionFailure("Too many auth responses sent")
        case (.server, .awaitingResponses(let attempts, let responseCount)):
            if success {
                self.state = .authenticationSucceeded
            } else if responseCount > 1 {
                self.state = .awaitingResponses(attempts: attempts, pending: responseCount - 1)
            } else {
                self.state = .awaitingNextRequest(attempts: attempts)
            }
        case (.server, .authenticationSucceeded):
            preconditionFailure("Authentication already succeeded, further messages are unnecessary.")
        case (.server, .authenticationFailed):
            preconditionFailure("Servers can never enter authenticationFailed")
        case (.client, _):
            preconditionFailure("Clients never send auth responses")
        }
    }
}

// MARK: Client authentication methods

extension UserAuthenticationStateMachine {
    /// Called to begin authentication in the state machine.
    func beginAuthentication() -> SSHMessage.ServiceRequestMessage? {
        switch (self.delegate, self.state) {
        case (.client, .idle):
            return SSHMessage.ServiceRequestMessage(service: Self.serviceName)
        case (.client, .awaitingServiceAcceptance),
            (.client, .awaitingNextRequest),
            (.client, .awaitingResponses),
            (.client, .authenticationSucceeded),
            (.client, .authenticationFailed):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure("Cannot start authentication twice, state: \(self.state)")
        case (.server, _):
            return nil
        }
    }

    /// Called when the last call to obtain an authentication request returned nil.
    mutating func noFurtherMethods() {
        switch (self.delegate, self.state) {
        case (.client, .awaitingNextRequest):
            self.state = .authenticationFailed
        case (.client, .idle),
            (.client, .awaitingServiceAcceptance):
            preconditionFailure("Ran out of auth methods before asking for any")
        case (.client, .awaitingResponses),
            (.client, .authenticationSucceeded),
            (.client, .authenticationFailed):
            // TODO(cory): We could probably support parallel auth attempts if we wanted to.
            preconditionFailure("Request for further auth failed when no such request should be outstanding")
        case (.server, _):
            preconditionFailure("Servers may not authenticate")
        }
    }
}

// MARK: Interacting with client delegate

extension UserAuthenticationStateMachine {
    fileprivate func requestNextAuthRequest(
        methods: NIOSSHAvailableUserAuthenticationMethods,
        serverOfferedMethodNames: [String],
        delegate: NIOSSHClientUserAuthenticationDelegate
    ) -> EventLoopFuture<SSHMessage.UserAuthRequestMessage?> {
        let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOffer?.self)
        // Brizmo patch: the names-carrying requirement; its default implementation calls the upstream one.
        delegate.nextAuthenticationType(
            availableMethods: methods,
            serverOfferedMethodNames: serverOfferedMethodNames,
            nextChallengePromise: promise
        )

        // The explicit capture list is here to force a copy of the buffer, rather than capturing self.
        return promise.futureResult.flatMapThrowing { [sessionID = self.sessionID] request in
            try request.map { try SSHMessage.UserAuthRequestMessage(request: $0, sessionID: sessionID) }
        }
    }
}

// MARK: Interacting with server delegate

extension UserAuthenticationStateMachine {
    /// Brizmo patch: routes keyboard-interactive requests (RFC 4256 §3.1) to the delegate's
    /// keyboard-interactive callback and everything else to the upstream `nextAuthResponse`.
    fileprivate mutating func nextAuthStep(
        request: SSHMessage.UserAuthRequestMessage,
        serial: UInt64,
        delegate: NIOSSHServerUserAuthenticationDelegate
    ) -> EventLoopFuture<NIOSSHUserAuthenticationServerStepMessage> {
        // `beginServerRequest` already aborted any keyboard-interactive attempt in progress: a late INFO_RESPONSE
        // to it is a protocol violation, and late delegate results or errors of that attempt are dropped.
        guard case .keyboardInteractive(let submethods) = request.method else {
            return self.nextAuthResponse(request: request, delegate: delegate).map { response in
                NIOSSHUserAuthenticationServerStepMessage.response(response)
            }
        }

        let supportedMethods = delegate.supportedAuthenticationMethods
        guard supportedMethods.contains(.keyboardInteractive) else {
            // Not offered: the usual failure listing what is supported.
            return self.loop.makeSucceededFuture(
                .response(.failure(.init(authentications: supportedMethods.strings, partialSuccess: false)))
            )
        }

        self.serverKeyboardInteractiveAttempt = (serial: serial, username: request.username)
        let keyboardInteractiveRequest = NIOSSHUserAuthenticationRequest(
            username: request.username,
            serviceName: request.service,
            request: .keyboardInteractive(.init(submethods: submethods))
        )
        let promise = self.loop.makePromise(of: NIOSSHKeyboardInteractiveServerStep.self)
        self.serverKeyboardInteractiveClock.withLockedValue { $0.callbackOutstanding = serial }
        delegate.keyboardInteractiveRequestReceived(request: keyboardInteractiveRequest, responsePromise: promise)

        return keyboardInteractiveStepFuture(
            promise.futureResult,
            serial: serial,
            clock: self.serverKeyboardInteractiveClock,
            supportedMethods: supportedMethods
        )
    }

    fileprivate func nextAuthResponse(
        request: SSHMessage.UserAuthRequestMessage,
        delegate: NIOSSHServerUserAuthenticationDelegate
    ) -> EventLoopFuture<NIOSSHUserAuthenticationResponseMessage> {
        switch request.method {
        case .password(let password):
            let request = NIOSSHUserAuthenticationRequest(
                username: request.username,
                serviceName: request.service,
                request: .password(.init(password: password))
            )
            let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
            delegate.requestReceived(request: request, responsePromise: promise)
            let supportedMethods = delegate.supportedAuthenticationMethods

            return promise.futureResult.map { outcome in
                .init(outcome, supportedMethods: supportedMethods)
            }

        case .publicKey(.known(key: let key, signature: .some(let signature))):
            // This is a direct request to auth, just pass it through.
            let dataToSign = UserAuthSignablePayload(
                sessionIdentifier: sessionID,
                userName: request.username,
                serviceName: request.service,
                publicKey: key
            )
            let supportedMethods = delegate.supportedAuthenticationMethods

            guard key.isValidSignature(signature, for: dataToSign) else {
                // Whoops, signature not valid.
                return self.loop.makeSucceededFuture(
                    .failure(.init(authentications: supportedMethods.strings, partialSuccess: false))
                )
            }

            // Signature is valid, ask if the delegate is happy.
            let request = NIOSSHUserAuthenticationRequest(
                username: request.username,
                serviceName: request.service,
                request: .publicKey(.init(publicKey: key))
            )
            let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
            delegate.requestReceived(request: request, responsePromise: promise)

            return promise.futureResult.map { outcome in
                .init(outcome, supportedMethods: supportedMethods)
            }

        case .publicKey(.known(key: let key, signature: .none)):
            // This is a weird wrinkle in public key auth: it's a request to ask whether a given key is valid, but not to validate that key itself.
            // For now we do a shortcut: we just say that all keys are acceptable, rather than ask the delegate.
            return self.loop.makeSucceededFuture(.publicKeyOK(.init(key: key)))

        case .publicKey(.unknown):
            // We don't known the algorithm, the auth attempt has failed.
            return self.loop.makeSucceededFuture(
                .failure(.init(authentications: delegate.supportedAuthenticationMethods.strings, partialSuccess: false))
            )

        case .none:
            let request = NIOSSHUserAuthenticationRequest(
                username: request.username,
                serviceName: request.service,
                request: .none
            )
            let promise = self.loop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
            delegate.requestReceived(request: request, responsePromise: promise)
            let supportedMethods = delegate.supportedAuthenticationMethods

            return promise.futureResult.map { outcome in
                .init(outcome, supportedMethods: supportedMethods)
            }

        case .keyboardInteractive:
            // Brizmo patch: not reached, `nextAuthStep` handles keyboard-interactive before calling us. Answered
            // like an unsupported method only to keep this switch exhaustive.
            return self.loop.makeSucceededFuture(
                .failure(.init(authentications: delegate.supportedAuthenticationMethods.strings, partialSuccess: false))
            )
        }
    }
}

/// Brizmo patch (server role): see `UserAuthenticationStateMachine.serverKeyboardInteractiveClock`.
struct KeyboardInteractiveClock {
    /// Serial of the latest USERAUTH_REQUEST received.
    var serial: UInt64 = 0
    /// Serial of the keyboard-interactive attempt whose delegate callback has not completed yet, if any.
    var callbackOutstanding: UInt64? = nil
}

/// Brizmo patch (server role, RFC 4252 §5.1): called when a keyboard-interactive delegate callback of the attempt
/// started by USERAUTH_REQUEST number `serial` completes, successfully or not. Marks the callback as no longer
/// outstanding and tells whether its attempt is still current. When it is not, a newer request has aborted the
/// attempt and already settled its pending answer, so the result must produce no message at all.
private func keyboardInteractiveCallbackIsCurrent(
    _ serial: UInt64,
    _ clock: NIOLockedValueBox<KeyboardInteractiveClock>
) -> Bool {
    clock.withLockedValue { clock in
        if clock.callbackOutstanding == serial {
            clock.callbackOutstanding = nil
        }
        return clock.serial == serial
    }
}

/// Brizmo patch (server role): the step future of a keyboard-interactive delegate callback. Both outcomes of the
/// delegate's promise are checked: a result or an error of an aborted attempt becomes `.abandoned` (no message,
/// no error, whatever state the connection is in by then); a current result goes out as usual and a current error
/// propagates as before.
private func keyboardInteractiveStepFuture(
    _ future: EventLoopFuture<NIOSSHKeyboardInteractiveServerStep>,
    serial: UInt64,
    clock: NIOLockedValueBox<KeyboardInteractiveClock>,
    supportedMethods: NIOSSHAvailableUserAuthenticationMethods
) -> EventLoopFuture<NIOSSHUserAuthenticationServerStepMessage> {
    future.map { step -> NIOSSHUserAuthenticationServerStepMessage in
        guard keyboardInteractiveCallbackIsCurrent(serial, clock) else { return .abandoned }  // stale result
        return NIOSSHUserAuthenticationServerStepMessage(step, supportedMethods: supportedMethods)
    }.flatMapErrorThrowing { error -> NIOSSHUserAuthenticationServerStepMessage in
        guard keyboardInteractiveCallbackIsCurrent(serial, clock) else { return .abandoned }  // stale error
        throw error
    }
}
