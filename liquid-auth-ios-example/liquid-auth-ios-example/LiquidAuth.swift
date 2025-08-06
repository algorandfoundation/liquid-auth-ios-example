/*
 * Copyright 2025 Algorand Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import AuthenticationServices
import CryptoKit
import Foundation
import LiquidAuthSDK
import SwiftCBOR
import WebRTC

#if canImport(UIKit)
    import UIKit
#endif

// MARK: - Protocols

/// Protocol for signing Liquid Auth challenges in the FIDO2 flow
/// Each wallet implements this to handle challenge signing with their specific key management
public protocol LiquidAuthChallengeSigner {
    /// Sign a challenge received from the Liquid Auth FIDO2 flow
    /// - Parameter challenge: The raw challenge bytes to sign
    /// - Returns: The signature bytes
    func signLiquidAuthChallenge(_ challenge: Data) async throws -> Data
}

/// Protocol for handling incoming messages during signaling
/// Wallets implement this to handle ARC27 transactions and other message types
public protocol LiquidAuthMessageHandler {
    /// Handle an incoming message and optionally return a response
    /// - Parameter message: The incoming message (base64URL encoded)
    /// - Returns: Optional response message (base64URL encoded) or nil if no response
    func handleMessage(_ message: String) async -> String?
}

// MARK: - Result

public struct LiquidAuthResult {
    public let success: Bool
    public let errorMessage: String?

    public init(success: Bool, errorMessage: String? = nil) {
        self.success = success
        self.errorMessage = errorMessage
    }

    public static func success() -> LiquidAuthResult {
        LiquidAuthResult(success: true)
    }

    public static func failure(_ message: String) -> LiquidAuthResult {
        LiquidAuthResult(success: false, errorMessage: message)
    }
}

// MARK: - Main Client

/// Main client for Liquid Auth operations
/// This is the primary entry point for the LiquidAuth system
///
/// Important: Both userAgent and device parameters must be provided by the calling application.
/// - userAgent should be in a format compatible with ua-parser-js. For example:
///   "liquid-auth/1.0 (iPhone; iOS 18.5)" or similar valid user agent strings.
/// - device should be a device identifier string (e.g., "iPhone", "iPad", "Mac", etc.)
public class LiquidAuthClient {
    public init() {}

    /// Register a new credential with Liquid Auth
    /// - Parameters:
    ///   - origin: The origin domain for the WebAuthn ceremony
    ///   - requestId: Unique identifier for this registration request
    ///   - algorandAddress: The Algorand address to associate with this credential
    ///   - challengeSigner: Handler for signing the Ed25519 Algorand Extension challenge
    ///   - p256KeyPair: The P256 key pair to use for the credential
    ///   - messageHandler: Handler for incoming messages during signaling
    ///   - userAgent: User agent string to send to the server (must be provided by the calling app)
    ///   - device: Device identifier string to send to the server (must be provided by the calling app)
    /// - Returns: Result indicating success or failure
    public func register(
        origin: String,
        requestId: String,
        algorandAddress: String,
        challengeSigner: LiquidAuthChallengeSigner,
        p256KeyPair: P256.Signing.PrivateKey,
        messageHandler: LiquidAuthMessageHandler,
        userAgent: String,
        device: String
    ) async throws -> LiquidAuthResult {
        // Use the implementation
        let result = try await performRegistration(
            origin: origin,
            requestId: requestId,
            algorandAddress: algorandAddress,
            challengeSigner: challengeSigner,
            p256KeyPair: p256KeyPair,
            userAgent: userAgent,
            device: device
        )

        if result.success {
            // Start signaling after successful registration
            try await startSignaling(
                origin: origin,
                requestId: requestId,
                messageHandler: messageHandler
            )
        }

        return result
    }

    /// Authenticate with an existing credential
    /// - Parameters:
    ///   - origin: The origin domain for the WebAuthn ceremony
    ///   - requestId: Unique identifier for this authentication request
    ///   - algorandAddress: The Algorand address associated with the credential
    ///   - challengeSigner: Handler for signing the WebAuthn challenge
    ///   - p256KeyPair: The P256 key pair associated with the credential
    ///   - messageHandler: Handler for incoming messages during signaling
    ///   - userAgent: User agent string to send to the server (must be provided by the calling app)
    ///   - device: Device identifier string to send to the server (must be provided by the calling app)
    /// - Returns: Result indicating success or failure
    public func authenticate(
        origin: String,
        requestId: String,
        algorandAddress: String,
        challengeSigner: LiquidAuthChallengeSigner,
        p256KeyPair: P256.Signing.PrivateKey,
        messageHandler: LiquidAuthMessageHandler,
        userAgent: String,
        device: String
    ) async throws -> LiquidAuthResult {
        // Use the implementation
        let result = try await performAuthentication(
            origin: origin,
            requestId: requestId,
            algorandAddress: algorandAddress,
            challengeSigner: challengeSigner,
            p256KeyPair: p256KeyPair,
            userAgent: userAgent,
            device: device
        )

        if result.success {
            // Start signaling after successful authentication
            try await startSignaling(
                origin: origin,
                requestId: requestId,
                messageHandler: messageHandler
            )
        }

        return result
    }
}

// MARK: - Implementation

/// Register implementation - contains all the complex WebAuthn logic
private func performRegistration(
    origin: String,
    requestId: String,
    algorandAddress: String,
    challengeSigner: LiquidAuthChallengeSigner,
    p256KeyPair: P256.Signing.PrivateKey,
    userAgent: String,
    device: String
) async throws -> LiquidAuthResult {
    // All this complex logic will be in the SDK
    let attestationApi = AttestationApi()

    let options: [String: Any] = [
        "username": algorandAddress,
        "displayName": "Liquid Auth User",
        "authenticatorSelection": ["userVerification": "required"],
        "extensions": ["liquid": true],
    ]

    // Post attestation options
    let (data, sessionCookie) = try await attestationApi.postAttestationOptions(
        origin: origin,
        userAgent: userAgent,
        options: options
    )

    Logger.debug("Response data: \(String(data: data, encoding: .utf8) ?? "Invalid data")")
    if let cookie = sessionCookie {
        Logger.debug("Session cookie: \(cookie)")
    }

    guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
          let challengeBase64Url = json["challenge"] as? String,
          let rp = json["rp"] as? [String: Any],
          let rpId = rp["id"] as? String
    else {
        throw NSError(domain: "com.liquidauth.error", code: -1,
                      userInfo: [NSLocalizedDescriptionKey: "Failed to parse response JSON"])
    }

    if origin != rpId {
        Logger.info("⚠️ Origin (\(origin)) and rpId (\(rpId)) are different.")
    }

    Logger.debug("Challenge (Base64): \(challengeBase64Url)")

    // Decode and sign the challenge using the provided signer
    let challengeBytes =
        Data([UInt8](Utility.decodeBase64Url(challengeBase64Url)!)) // Pass the base64URL string as bytes

    let signature = try await challengeSigner.signLiquidAuthChallenge(challengeBytes)

    Logger.debug("Signature: \(signature.base64URLEncodedString())")

    // Create the Liquid extension JSON object
    let liquidExt = [
        "type": "algorand",
        "requestId": requestId,
        "address": algorandAddress,
        "signature": signature.base64URLEncodedString(),
        "device": device,
    ]

    Logger.debug("Created liquidExt JSON object: \(liquidExt)")

    // Deterministic ID - derived from P256 Public Key
    let rawId = Data([UInt8](LiquidAuthSDK.Utility.hashSHA256(p256KeyPair.publicKey.rawRepresentation)))
    Logger.debug("Created rawId: \(rawId.map { String(format: "%02hhx", $0) }.joined())")

    // Create clientDataJSON
    let clientData: [String: Any] = [
        "type": "webauthn.create",
        "challenge": challengeBase64Url,
        "origin": "https://\(rpId)",
    ]

    guard let clientDataJSONData = try? JSONSerialization.data(withJSONObject: clientData, options: []) else {
        throw NSError(domain: "com.liquidauth.error", code: -1,
                      userInfo: [NSLocalizedDescriptionKey: "Failed to create clientDataJSON"])
    }

    let clientDataJSONBase64Url = clientDataJSONData.base64URLEncodedString()
    Logger.debug("Created clientDataJSON: \(clientDataJSONBase64Url)")

    // Create attestationObject
    let attestedCredData = LiquidAuthSDK.Utility.getAttestedCredentialData(
        aaguid: UUID(uuidString: "1F59713A-C021-4E63-9158-2CC5FDC14E52")!,
        credentialId: rawId,
        publicKey: p256KeyPair.publicKey.rawRepresentation
    )

    Logger.debug("created attestedCredData: \(attestedCredData.count)")

    let rpIdHash = LiquidAuthSDK.Utility.hashSHA256(rpId.data(using: .utf8)!)
    let authData = AuthenticatorData.attestation(
        rpIdHash: rpIdHash,
        userPresent: true,
        userVerified: true,
        backupEligible: true,
        backupState: true,
        signCount: 0,
        attestedCredentialData: attestedCredData,
        extensions: nil
    )
    Logger.debug("created authData: \(authData)")

    let attObj: [String: Any] = [
        "attStmt": [:],
        "authData": authData.toData(),
        "fmt": "none",
    ]

    let cborEncoded = try CBOR.encodeMap(attObj)
    let attestationObject = Data(cborEncoded)
    Logger.debug("Created attestationobject: \(attestationObject.base64URLEncodedString())")

    let credential: [String: Any] = [
        "id": rawId.base64URLEncodedString(),
        "type": "public-key",
        "rawId": rawId.base64URLEncodedString(),
        "response": [
            "clientDataJSON": clientDataJSONBase64Url,
            "attestationObject": attestationObject.base64URLEncodedString(),
        ],
    ]
    Logger.debug("Created credential: \(credential)")

    // Post attestation result
    let responseData = try await attestationApi.postAttestationResult(
        origin: origin,
        userAgent: userAgent,
        credential: credential,
        liquidExt: liquidExt,
        device: device
    )

    // Handle the server response
    let responseString = String(data: responseData, encoding: .utf8) ?? "Invalid response"
    Logger.info("Attestation result posted: \(responseString)")

    // Parse the response to check for errors
    if let responseJSON = try? JSONSerialization.jsonObject(with: responseData, options: []) as? [String: Any],
       let errorReason = responseJSON["error"] as? String
    {
        Logger.error("Registration failed: \(errorReason)")
        return LiquidAuthResult(success: false, errorMessage: "Registration failed: \(errorReason)")
    } else {
        Logger.info("Registration completed successfully.")
        return LiquidAuthResult(success: true)
    }
}

/// Authenticate implementation - contains all the complex WebAuthn logic
private func performAuthentication(
    origin: String,
    requestId: String,
    algorandAddress: String,
    challengeSigner: LiquidAuthChallengeSigner,
    p256KeyPair: P256.Signing.PrivateKey,
    userAgent: String,
    device: String
) async throws -> LiquidAuthResult {
    let assertionApi = AssertionApi()

    let credentialId = Data([UInt8](LiquidAuthSDK.Utility.hashSHA256(p256KeyPair.publicKey.rawRepresentation)))
        .base64URLEncodedString()

    // Call postAssertionOptions
    let (data, sessionCookie) = try await assertionApi.postAssertionOptions(
        origin: origin,
        userAgent: userAgent,
        credentialId: credentialId
    )

    if let sessionCookie {
        Logger.debug("Session cookie: \(sessionCookie)")
    }

    // Parse the response data
    guard let json = try? JSONSerialization.jsonObject(with: data, options: []) as? [String: Any],
          let challengeBase64Url = json["challenge"] as? String
    else {
        throw NSError(domain: "com.liquidauth.error", code: -1,
                      userInfo: [NSLocalizedDescriptionKey: "Failed to parse response JSON"])
    }

    // Support both "rp": { "id": ... } and "rpId": ...
    let rpId: String
    if let rp = json["rp"] as? [String: Any], let id = rp["id"] as? String {
        rpId = id
    } else if let id = json["rpId"] as? String {
        rpId = id
    } else {
        throw NSError(domain: "com.liquidauth.error", code: -1,
                      userInfo: [NSLocalizedDescriptionKey: "Failed to find rpId in response."])
    }

    if origin != rpId {
        Logger.info("⚠️ Origin (\(origin)) and rpId (\(rpId)) are different.")
    }

    Logger.debug("Challenge (Base64): \(challengeBase64Url)")

    // Decode and sign the challenge using the provided signer
    let challengeBytes =
        Data([UInt8](Utility.decodeBase64Url(challengeBase64Url)!)) // Pass the base64URL string as bytes

    let signature = try await challengeSigner.signLiquidAuthChallenge(challengeBytes)

    Logger.debug("Signature: \(signature.base64URLEncodedString())")

    // Create the Liquid extension JSON object
    let liquidExt = [
        "type": "algorand",
        "requestId": requestId,
        "address": algorandAddress,
        "signature": signature.base64URLEncodedString(),
        "device": device,
    ]

    Logger.debug("Created liquidExt JSON object: \(liquidExt)")

    // Create clientDataJSON
    let clientData: [String: Any] = [
        "type": "webauthn.get",
        "challenge": challengeBase64Url,
        "origin": "https://\(rpId)",
    ]

    guard let clientDataJSONData = try? JSONSerialization.data(withJSONObject: clientData, options: []) else {
        throw NSError(domain: "com.liquidauth.error", code: -1,
                      userInfo: [NSLocalizedDescriptionKey: "Failed to create clientDataJSON"])
    }

    let clientDataJSONBase64Url = clientDataJSONData.base64URLEncodedString()
    Logger.debug("Created clientDataJSON: \(clientDataJSONBase64Url)")

    let rpIdHash = LiquidAuthSDK.Utility.hashSHA256(rpId.data(using: .utf8)!)
    let authenticatorData = AuthenticatorData.assertion(
        rpIdHash: rpIdHash,
        userPresent: true,
        userVerified: true,
        backupEligible: false,
        backupState: false
    ).toData()

    let clientDataHash = LiquidAuthSDK.Utility.hashSHA256(clientDataJSONData)
    let dataToSign = authenticatorData + clientDataHash

    let p256Signature = try p256KeyPair.signature(for: dataToSign)

    let assertionResponse: [String: Any] = [
        "id": credentialId,
        "type": "public-key",
        "userHandle": "tester",
        "rawId": credentialId,
        "response": [
            "clientDataJSON": clientDataJSONData.base64URLEncodedString(),
            "authenticatorData": authenticatorData.base64URLEncodedString(),
            "signature": p256Signature.derRepresentation.base64URLEncodedString(),
        ],
    ]

    Logger.debug("Created assertion response: \(assertionResponse)")

    // Serialize the assertion response into a JSON string
    guard let assertionResponseData = try? JSONSerialization.data(withJSONObject: assertionResponse, options: []),
          let assertionResponseJSON = String(data: assertionResponseData, encoding: .utf8)
    else {
        throw NSError(domain: "com.liquidauth.error", code: -1,
                      userInfo: [NSLocalizedDescriptionKey: "Failed to serialize assertion response"])
    }

    // Post the assertion result
    let responseData = try await assertionApi.postAssertionResult(
        origin: origin,
        userAgent: userAgent,
        credential: assertionResponseJSON,
        liquidExt: liquidExt
    )

    // Handle the server response
    let responseString = String(data: responseData, encoding: .utf8) ?? "Invalid response"
    Logger.info("Assertion result posted: \(responseString)")

    // Parse the response to check for errors
    if let responseJSON = try? JSONSerialization.jsonObject(with: responseData, options: []) as? [String: Any],
       let errorReason = responseJSON["error"] as? String
    {
        Logger.error("Authentication failed: \(errorReason)")
        return LiquidAuthResult(success: false, errorMessage: "Authentication failed: \(errorReason)")
    } else {
        Logger.info("Authentication completed successfully.")
        return LiquidAuthResult(success: true)
    }
}

/// Start signaling for peer-to-peer communication
private func startSignaling(
    origin: String,
    requestId: String,
    messageHandler: LiquidAuthMessageHandler
) async throws {
    let signalService = SignalService.shared

    signalService.start(url: origin, httpClient: URLSession.shared)

    let NODELY_TURN_USERNAME = "liquid-auth"
    let NODELY_TURN_CREDENTIAL = "sqmcP4MiTKMT4TGEDSk9jgHY"

    let iceServers = [
        RTCIceServer(
            urlStrings: [
                "stun:stun.l.google.com:19302",
                "stun:stun1.l.google.com:19302",
                "stun:stun2.l.google.com:19302",
                "stun:stun3.l.google.com:19302",
                "stun:stun4.l.google.com:19302",
            ]
        ),
        RTCIceServer(
            urlStrings: [
                "turn:global.turn.nodely.network:80?transport=tcp",
                "turns:global.turn.nodely.network:443?transport=tcp",
                "turn:eu.turn.nodely.io:80?transport=tcp",
                "turns:eu.turn.nodely.io:443?transport=tcp",
                "turn:us.turn.nodely.io:80?transport=tcp",
                "turns:us.turn.nodely.io:443?transport=tcp",
            ],
            username: NODELY_TURN_USERNAME,
            credential: NODELY_TURN_CREDENTIAL
        ),
    ]

    signalService.connectToPeer(
        requestId: requestId,
        type: "answer",
        origin: origin,
        iceServers: iceServers,
        onMessage: { message in
            Logger.info("💬 Received message: \(message)")

            Task {
                if let response = await messageHandler.handleMessage(message) {
                    signalService.sendMessage(response)
                }
            }
        },
        onStateChange: { state in
            if state == "open" {
                Logger.info("✅ Data channel is OPEN")
                signalService.sendMessage("ping")
            }
        }
    )
}
