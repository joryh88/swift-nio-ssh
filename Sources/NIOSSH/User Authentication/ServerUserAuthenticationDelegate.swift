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
// Modified by the Brizmo project (2026-11-01): keyboard-interactive request/response callbacks
// (RFC 4256) with default implementations, so existing conformers compile unchanged. See BRIZMO-PATCH.md.
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A ``NIOSSHServerUserAuthenticationDelegate`` is an object that can authorize users.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, in many cases it may be necessary to read files
/// from disk. This is enabled by allowing implementers to satisfy a promise, rather than
/// requiring that they synchronously provide a response.
///
/// Implementers should be aware that multiple authentication requests may be in flight at once:
/// they must be responded to in order. It is up to implementers to meet this requirement, it is
/// not enforced by the implementation.
public protocol NIOSSHServerUserAuthenticationDelegate {
    /// The authentication methods this delegate is willing to receive.
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods { get }

    /// A user authentication request has been received.
    ///
    /// - parameters:
    ///     - request: The received user authentication request
    ///     - responsePromise: An `EventLoopPromise` that must be completed with the outcome of the user auth attempt.
    func requestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>
    )

    /// A keyboard-interactive USERAUTH_REQUEST (RFC 4256 §3.1) has been received. Added by the Brizmo project.
    ///
    /// Only called when ``supportedAuthenticationMethods`` contains
    /// ``NIOSSHAvailableUserAuthenticationMethods/keyboardInteractive``; otherwise NIOSSH answers FAILURE
    /// itself. Complete `responsePromise` with a challenge (sent as SSH_MSG_USERAUTH_INFO_REQUEST) or an
    /// outcome. The default implementation answers `.outcome(.failure)`. If the client sends a new
    /// USERAUTH_REQUEST before the promise is completed, this attempt is aborted (RFC 4252 §5.1): whatever the
    /// promise is completed with later — including an error — is dropped and nothing is sent for it. The same
    /// holds for ``keyboardInteractiveResponseReceived(username:response:responsePromise:)``.
    ///
    /// - parameters:
    ///     - request: The received request; its `request` is `.keyboardInteractive`.
    ///     - responsePromise: An `EventLoopPromise` that must be completed with the next step.
    func keyboardInteractiveRequestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    )

    /// The client answered our last keyboard-interactive challenge (SSH_MSG_USERAUTH_INFO_RESPONSE,
    /// RFC 4256 §3.4). Added by the Brizmo project.
    ///
    /// Only called when the number of responses equals the number of prompts we sent; a mismatch is answered
    /// with FAILURE by NIOSSH without calling this. Complete `responsePromise` with another challenge or an
    /// outcome. Responses do not count toward `maxAuthAttempts` (only USERAUTH_REQUEST messages do). The
    /// default implementation answers `.outcome(.failure)`.
    ///
    /// - parameters:
    ///     - username: The user name of the keyboard-interactive request this response belongs to.
    ///     - response: The client's answers, one per prompt.
    ///     - responsePromise: An `EventLoopPromise` that must be completed with the next step.
    func keyboardInteractiveResponseReceived(
        username: String,
        response: NIOSSHKeyboardInteractiveResponse,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    )
}

extension NIOSSHServerUserAuthenticationDelegate {
    /// Default (Brizmo patch): a delegate that does not implement keyboard-interactive rejects it.
    public func keyboardInteractiveRequestReceived(
        request: NIOSSHUserAuthenticationRequest,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    ) {
        responsePromise.succeed(.outcome(.failure))
    }

    /// Default (Brizmo patch): a delegate that does not implement keyboard-interactive rejects it.
    public func keyboardInteractiveResponseReceived(
        username: String,
        response: NIOSSHKeyboardInteractiveResponse,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveServerStep>
    ) {
        responsePromise.succeed(.outcome(.failure))
    }
}
