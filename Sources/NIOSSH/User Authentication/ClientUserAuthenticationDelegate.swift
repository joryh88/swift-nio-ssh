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
// Modified by the Brizmo project (2026-11-01): keyboard-interactive challenge callback (RFC 4256) and a
// variant of `nextAuthenticationType` that also receives the server's method names verbatim, both with
// default implementations, so existing conformers compile unchanged. See BRIZMO-PATCH.md.
//
//===----------------------------------------------------------------------===//

import NIOCore

/// A ``NIOSSHClientUserAuthenticationDelegate`` is an object that can provide a sequence of
/// SSH user authentication methods based on the the acceptable list from the server.
///
/// This protocol defines the interface that will be used by the user authentication state
/// machine to move forward with challenges. Implementers of this protocol are free to take
/// time to actually get responses: for example, for password authentication it is possible
/// that the application would like to provide a user-interactive password prompt. This is
/// enabled by allowing implementers to satisfy a promise, rather than requiring that they
/// synchronously provide a response.
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentication methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    ///
    /// - parameters:
    ///     - availableMethods: The authentication methods the server is willing to accept.
    ///     - nextChallengePromise: An `EventLoopPromise` to be fulfilled with the next authentication offer.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )

    /// Same as ``nextAuthenticationType(availableMethods:nextChallengePromise:)``, plus the method names exactly
    /// as the server listed them in its last SSH_MSG_USERAUTH_FAILURE (RFC 4252 §5.1), including names NIOSSH
    /// does not know (which `availableMethods` cannot represent). Empty on the first call, before the server has
    /// listed anything. NIOSSH calls this one; the default implementation calls the upstream requirement.
    /// Added by the Brizmo project.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        serverOfferedMethodNames: [String],
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )

    /// Called when the server sends a keyboard-interactive challenge (SSH_MSG_USERAUTH_INFO_REQUEST,
    /// RFC 4256 §3.2) for the ``NIOSSHUserAuthenticationOffer/Offer-swift.enum/keyboardInteractive(_:)`` offer
    /// currently in flight. Added by the Brizmo project.
    ///
    /// Complete `responsePromise` with exactly one response per prompt (`responses.count ==
    /// challenge.prompts.count`, RFC 4256 §3.4; zero prompts need zero responses). A response with a different
    /// count fails the connection instead of being sent. The server may send several challenges for one
    /// offer; there is no limit here, so a delegate that wants one must count rounds itself and fail the
    /// promise. Failing the promise terminates connection establishment, like failing `nextChallengePromise`.
    ///
    /// The default implementation fails the promise with ``NIOSSHError/ErrorType-swift.struct/keyboardInteractiveChallengeUnhandled``.
    ///
    /// - parameters:
    ///     - challenge: The prompts sent by the server.
    ///     - responsePromise: An `EventLoopPromise` to be fulfilled with the answers.
    func keyboardInteractiveChallengeReceived(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveResponse>
    )
}

extension NIOSSHClientUserAuthenticationDelegate {
    /// Default (Brizmo patch): delegates written before this requirement existed ignore the names.
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        serverOfferedMethodNames: [String],
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        self.nextAuthenticationType(availableMethods: availableMethods, nextChallengePromise: nextChallengePromise)
    }

    /// Default (Brizmo patch): delegates written before keyboard-interactive support never offer it, so a
    /// challenge reaching them is unexpected; fail instead of guessing an answer.
    public func keyboardInteractiveChallengeReceived(
        _ challenge: NIOSSHKeyboardInteractiveChallenge,
        responsePromise: EventLoopPromise<NIOSSHKeyboardInteractiveResponse>
    ) {
        responsePromise.fail(NIOSSHError.keyboardInteractiveChallengeUnhandled)
    }
}
