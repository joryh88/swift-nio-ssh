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
// Modified by the Brizmo project (2026-11-01): keyboard-interactive user authentication
// (RFC 4256) method bit, offer/request cases and challenge/response types. See BRIZMO-PATCH.md.
//
//===----------------------------------------------------------------------===//
import NIOCore

/// The user authentication modes available at this point in time.
///
/// User authentication in SSH proceeds in a dynamic fashion, and it is possible to require multiple forms
/// of authentication sequentially, or to be able to accept one of many forms.
public struct NIOSSHAvailableUserAuthenticationMethods: OptionSet, Sendable {
    public var rawValue: UInt8

    public init(rawValue: UInt8) {
        self.rawValue = rawValue
    }

    /// Public key authentication is acceptable.
    public static let publicKey: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 0)

    /// Password-based authentication is acceptable.
    public static let password: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 1)

    /// Host-based authentication is acceptable.
    public static let hostBased: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 2)

    /// Keyboard-interactive authentication (RFC 4256) is acceptable. Added by the Brizmo project.
    ///
    /// Deliberately **not** part of ``all``: `.all` is what existing server delegates (for example
    /// ``DenyAllServerAuthDelegate``) advertise in USERAUTH_FAILURE, and adding a method there would change
    /// what those servers put on the wire. A server opts in by listing `.keyboardInteractive` explicitly.
    public static let keyboardInteractive: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 3)

    /// A short-hand for all supported authentication types.
    public static let all: NIOSSHAvailableUserAuthenticationMethods = [.publicKey, .password, .hostBased]
}

extension NIOSSHAvailableUserAuthenticationMethods {
    internal init(_ message: SSHMessage.UserAuthFailureMessage) {
        self = .init()

        for message in message.authentications {
            switch message {
            case "publickey":
                self.insert(.publicKey)
            case "password":
                self.insert(.password)
            case "hostbased":
                self.insert(.hostBased)
            case "keyboard-interactive":
                // Brizmo patch (RFC 4256): upstream dropped this name in `default:` below, so a
                // keyboard-interactive-only server looked like it offered nothing at all.
                self.insert(.keyboardInteractive)
            default:
                // This is an unknown method, which we ignore.
                break
            }
        }
    }

    internal var strings: [Substring] {
        guard self != .init() else {
            return []
        }

        // We need an array.
        var methods = [Substring]()
        methods.reserveCapacity(4)

        if self.contains(.password) {
            methods.append("password")
        }
        if self.contains(.publicKey) {
            methods.append("publickey")
        }
        if self.contains(.hostBased) {
            methods.append("hostbased")
        }
        if self.contains(.keyboardInteractive) {
            methods.append("keyboard-interactive")
        }

        return methods
    }
}

extension NIOSSHAvailableUserAuthenticationMethods: Hashable {}

/// A specific request for user authentication. This type is the one observed from the server side. The
/// associated client side type is ``NIOSSHUserAuthenticationOffer``.
public struct NIOSSHUserAuthenticationRequest: Sendable {
    /// The username for which the client would like to authenticate.
    public var username: String

    /// The specific authentication request.
    public var request: Request

    public init(username: String, serviceName: String, request: Request) {
        self.username = username
        self.request = request
    }
}

extension NIOSSHUserAuthenticationRequest {
    /// ``NIOSSHUserAuthenticationRequest/Request-swift.enum`` describes the kind of authentication attempt the client is making.
    public enum Request: Sendable {
        /// The client would like to perform public key authentication.
        case publicKey(PublicKey)

        /// The client would like to perform password authentication.
        case password(Password)

        /// The client would like to perform host-based authentication.
        ///
        /// This method is currently unsupported by ``NIOSSH``.
        case hostBased(HostBased)

        /// The client believes it does not need authentication.
        case none

        /// The client would like to perform keyboard-interactive authentication (RFC 4256).
        ///
        /// The server delegate answers it through
        /// ``NIOSSHServerUserAuthenticationDelegate/keyboardInteractiveRequestReceived(request:responsePromise:)``,
        /// not through `requestReceived`. Added by the Brizmo project.
        case keyboardInteractive(KeyboardInteractive)
    }
}

extension NIOSSHUserAuthenticationRequest.Request {
    /// Information provided by the client when starting keyboard-interactive authentication (RFC 4256 §3.1).
    /// Added by the Brizmo project.
    public struct KeyboardInteractive: Sendable {
        /// The submethods the client suggests (RFC 4256 §3.1); usually empty. Servers may ignore them.
        public var submethods: [String]

        public init(submethods: [String]) {
            self.submethods = submethods
        }
    }

    /// Information provided by the client when attempting to perform a public-key authentication.
    public struct PublicKey: Sendable {
        /// The user's public key.
        public var publicKey: NIOSSHPublicKey

        public init(publicKey: NIOSSHPublicKey) {
            self.publicKey = publicKey
        }
    }

    /// Information provided by the client when attempting to perform password-based authentication.
    public struct Password: Sendable {
        /// The user's password.
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    /// Information provided by the client when attempting to perform host-based authentication.
    ///
    /// This method is currently unsupported by ``NIOSSH``.
    public struct HostBased: Sendable {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}

extension NIOSSHUserAuthenticationRequest: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.PublicKey: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.Password: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.HostBased: Hashable {}

extension NIOSSHUserAuthenticationRequest.Request.KeyboardInteractive: Hashable {}

/// A specific offer of user authentication. This type is the one used on the client side. The
/// associated server side type is ``NIOSSHUserAuthenticationRequest``.
public struct NIOSSHUserAuthenticationOffer: Sendable {
    /// The username for which the client would like to authenticate.
    public var username: String

    /// The specific authentication offer.
    public var offer: Offer

    public init(username: String, serviceName: String, offer: Offer) {
        self.username = username
        self.offer = offer
    }
}

extension NIOSSHUserAuthenticationOffer {
    /// ``NIOSSHUserAuthenticationOffer/Offer-swift.enum`` describes the kind of authentication offer the client is making.
    public enum Offer: Sendable {
        /// The client would like to perform private key authentication.
        case privateKey(PrivateKey)

        /// The client would like to perform password authentication.
        case password(Password)

        /// The client would like to perform host-based authentication.
        ///
        /// This method is currently unsupported by ``NIOSSH``.
        case hostBased(HostBased)

        /// The client believes it does not need authentication.
        case none

        /// The client would like to perform keyboard-interactive authentication (RFC 4256).
        ///
        /// The server's prompts are delivered to
        /// ``NIOSSHClientUserAuthenticationDelegate/keyboardInteractiveChallengeReceived(_:responsePromise:)``.
        /// Added by the Brizmo project.
        case keyboardInteractive(KeyboardInteractive)
    }
}

extension NIOSSHUserAuthenticationOffer.Offer {
    /// Information provided by the client when starting keyboard-interactive authentication (RFC 4256 §3.1).
    /// Added by the Brizmo project.
    public struct KeyboardInteractive: Sendable {
        /// Submethods to suggest to the server (RFC 4256 §3.1). Leave empty unless the server documents them.
        public var submethods: [String]

        public init(submethods: [String] = []) {
            self.submethods = submethods
        }
    }

    /// Information provided by the client when attempting to perform private key authentication.
    public struct PrivateKey: Sendable {
        /// The client's private key.
        ///
        /// This is not sent to the server, but is used by ``NIOSSH`` to respond to auth challenges.
        public var privateKey: NIOSSHPrivateKey

        /// The client's public key.
        ///
        /// This is sent to the server.
        public var publicKey: NIOSSHPublicKey

        public init(privateKey: NIOSSHPrivateKey) {
            self.privateKey = privateKey
            self.publicKey = privateKey.publicKey
        }

        public init(privateKey: NIOSSHPrivateKey, certifiedKey: NIOSSHCertifiedPublicKey) {
            self.privateKey = privateKey
            self.publicKey = NIOSSHPublicKey(certifiedKey)
        }
    }

    /// Information provided by the client when attempting to perform password-based authentication.
    public struct Password: Sendable {
        /// The client's password.
        public var password: String

        public init(password: String) {
            self.password = password
        }
    }

    /// Information provided by the client when attempting to perform host-based authentication.
    ///
    /// This method is currently unsupported by ``NIOSSH``.
    public struct HostBased: Sendable {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}

extension SSHMessage.UserAuthRequestMessage {
    init(request: NIOSSHUserAuthenticationOffer, sessionID: ByteBuffer) throws {
        // We only ever ask for the ssh-connection service.
        self.username = request.username
        self.service = "ssh-connection"

        switch request.offer {
        case .privateKey(let privateKeyRequest):
            let dataToSign = UserAuthSignablePayload(
                sessionIdentifier: sessionID,
                userName: self.username,
                serviceName: self.service,
                publicKey: privateKeyRequest.publicKey
            )
            let signature = try privateKeyRequest.privateKey.sign(dataToSign)
            self.method = .publicKey(.known(key: privateKeyRequest.publicKey, signature: signature))
        case .password(let passwordRequest):
            self.method = .password(passwordRequest.password)
        case .hostBased:
            fatalError("Unsupported")
        case .none:
            self.method = .none
        case .keyboardInteractive(let keyboardInteractive):
            self.method = .keyboardInteractive(submethods: keyboardInteractive.submethods)
        }
    }
}

// MARK: - Keyboard-interactive challenge and response (Brizmo patch, RFC 4256)

/// One round of keyboard-interactive prompts sent by the server (SSH_MSG_USERAUTH_INFO_REQUEST, RFC 4256 §3.2).
///
/// Added by the Brizmo project.
public struct NIOSSHKeyboardInteractiveChallenge: Hashable, Sendable {
    /// One prompt. `echo == false` means the answer is secret (for example a password).
    public struct Prompt: Hashable, Sendable {
        public var text: String
        public var echo: Bool

        public init(text: String, echo: Bool) {
            self.text = text
            self.echo = echo
        }
    }

    public var name: String
    public var instruction: String
    /// Deprecated by RFC 4256 §3.2; usually empty.
    public var languageTag: String
    /// May be empty: RFC 4256 §3.4 still requires an (empty) response in that case.
    public var prompts: [Prompt]

    public init(name: String = "", instruction: String = "", languageTag: String = "", prompts: [Prompt]) {
        self.name = name
        self.instruction = instruction
        self.languageTag = languageTag
        self.prompts = prompts
    }
}

/// The client's answers to one ``NIOSSHKeyboardInteractiveChallenge`` (SSH_MSG_USERAUTH_INFO_RESPONSE,
/// RFC 4256 §3.4). `responses.count` must equal the challenge's `prompts.count`; NIOSSH fails the connection
/// rather than send a response with a different count.
///
/// Added by the Brizmo project.
public struct NIOSSHKeyboardInteractiveResponse: Hashable, Sendable {
    public var responses: [String]

    public init(responses: [String]) {
        self.responses = responses
    }
}

/// What a server user authentication delegate does next in a keyboard-interactive exchange: ask (another)
/// round of prompts, or finish the attempt. Added by the Brizmo project.
public enum NIOSSHKeyboardInteractiveServerStep: Sendable {
    /// Send these prompts to the client (SSH_MSG_USERAUTH_INFO_REQUEST).
    case challenge(NIOSSHKeyboardInteractiveChallenge)

    /// Finish the attempt with SUCCESS or FAILURE, exactly like `requestReceived`.
    case outcome(NIOSSHUserAuthenticationOutcome)
}

extension NIOSSHKeyboardInteractiveChallenge {
    init(_ message: SSHMessage.UserAuthInfoRequestMessage) {
        self.init(
            name: message.name,
            instruction: message.instruction,
            languageTag: message.languageTag,
            prompts: message.prompts.map { Prompt(text: $0.prompt, echo: $0.echo) }
        )
    }
}

extension SSHMessage.UserAuthInfoRequestMessage {
    init(_ challenge: NIOSSHKeyboardInteractiveChallenge) {
        self.init(
            name: challenge.name,
            instruction: challenge.instruction,
            languageTag: challenge.languageTag,
            prompts: challenge.prompts.map { Prompt(prompt: $0.text, echo: $0.echo) }
        )
    }
}

/// The outcome of a user authentication attempt.
public enum NIOSSHUserAuthenticationOutcome: Sendable {
    /// The authentication attempt succeeded and the client is authenticated.
    case success

    /// The authentication attempt partially succeeded, but additional authentication is required.
    ///
    /// The additional authentication requirements are described in `remainingMethods`.
    case partialSuccess(remainingMethods: NIOSSHAvailableUserAuthenticationMethods)

    /// The authentication attempt failed.
    case failure
}

enum NIOSSHUserAuthenticationResponseMessage {
    case success
    case failure(SSHMessage.UserAuthFailureMessage)
    case publicKeyOK(SSHMessage.UserAuthPKOKMessage)
    case disconnect(SSHMessage.DisconnectMessage)
}

/// Brizmo patch (RFC 4256): what the server sends back for one USERAUTH_REQUEST or INFO_RESPONSE.
///
/// A separate type, rather than a new case on ``NIOSSHUserAuthenticationResponseMessage``, so that every
/// existing exhaustive switch over that type (including upstream tests) is unchanged.
enum NIOSSHUserAuthenticationServerStepMessage {
    case response(NIOSSHUserAuthenticationResponseMessage)
    case infoRequest(SSHMessage.UserAuthInfoRequestMessage)
    /// The keyboard-interactive attempt this result belongs to was aborted by a newer USERAUTH_REQUEST
    /// (RFC 4252 §5.1): send nothing, report nothing.
    case abandoned
}

extension NIOSSHUserAuthenticationServerStepMessage {
    init(_ step: NIOSSHKeyboardInteractiveServerStep, supportedMethods: NIOSSHAvailableUserAuthenticationMethods) {
        switch step {
        case .challenge(let challenge):
            self = .infoRequest(.init(challenge))
        case .outcome(let outcome):
            self = .response(.init(outcome, supportedMethods: supportedMethods))
        }
    }
}

extension NIOSSHUserAuthenticationResponseMessage {
    init(_ outcome: NIOSSHUserAuthenticationOutcome, supportedMethods: NIOSSHAvailableUserAuthenticationMethods) {
        switch outcome {
        case .success:
            self = .success
        case .partialSuccess(remainingMethods: let remaining):
            let message = SSHMessage.UserAuthFailureMessage(authentications: remaining.strings, partialSuccess: true)
            self = .failure(message)
        case .failure:
            let message = SSHMessage.UserAuthFailureMessage(
                authentications: supportedMethods.strings,
                partialSuccess: false
            )
            self = .failure(message)
        }
    }
}
