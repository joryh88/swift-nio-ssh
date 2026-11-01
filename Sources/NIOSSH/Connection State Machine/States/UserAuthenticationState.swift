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
// Modified by the Brizmo project (2026-11-01): switches the packet parser's user-auth message context
// for keyboard-interactive (RFC 4256). See BRIZMO-PATCH.md.
//
//===----------------------------------------------------------------------===//

import NIOCore

extension SSHConnectionStateMachine {
    /// The state of a state machine that is actively engaged in a user authentication operation.
    struct UserAuthenticationState {
        /// The role of the connection
        let role: SSHConnectionRole

        /// The packet parser.
        var parser: SSHPacketParser

        /// The packet serializer used by this state machine.
        var serializer: SSHPacketSerializer

        var remoteVersion: String

        var protectionSchemes: [NIOSSHTransportProtection.Type]

        var sessionIdentifier: ByteBuffer

        /// The backing state machine.
        var userAuthStateMachine: UserAuthenticationStateMachine

        init(sentNewKeysState state: SentNewKeysState) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.userAuthStateMachine = state.userAuthStateMachine
            self.remoteVersion = state.remoteVersion
            self.protectionSchemes = state.protectionSchemes
            self.sessionIdentifier = state.sessionIdentifier
        }

        init(receivedNewKeysState state: ReceivedNewKeysState) {
            self.role = state.role
            self.parser = state.parser
            self.serializer = state.serializer
            self.userAuthStateMachine = state.userAuthStateMachine
            self.remoteVersion = state.remoteVersion
            self.protectionSchemes = state.protectionSchemes
            self.sessionIdentifier = state.sessionIdentifier
        }

        mutating func bufferInboundData(_ data: inout ByteBuffer) {
            self.parser.append(bytes: &data)
        }

        /// Brizmo patch (RFC 4252 §6, RFC 4256 §3.2): message number 60 means INFO_REQUEST while our
        /// keyboard-interactive request is in flight and PK_OK otherwise. Only a client receives 60, so only
        /// the client switches its parser; this is the only place the context is set.
        mutating func updateUserAuthMessageContext(afterSending message: SSHMessage.UserAuthRequestMessage) {
            guard self.role.isClient else {
                return
            }
            switch message.method {
            case .keyboardInteractive:
                self.parser.userAuthMessageContext = .keyboardInteractive
            case .none, .password, .publicKey:
                self.parser.userAuthMessageContext = .default
            }
        }

        /// Brizmo patch: USERAUTH_SUCCESS/FAILURE ends the request in flight; 60 means PK_OK again.
        mutating func resetUserAuthMessageContext() {
            self.parser.userAuthMessageContext = .default
        }
    }
}

extension SSHConnectionStateMachine.UserAuthenticationState: AcceptsUserAuthMessages {}

extension SSHConnectionStateMachine.UserAuthenticationState: SendsUserAuthMessages {}
