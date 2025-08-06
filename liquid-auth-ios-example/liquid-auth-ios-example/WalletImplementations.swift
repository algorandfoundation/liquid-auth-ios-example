import Base32
import CryptoKit
import deterministicP256_swift
import Foundation
import JSONSchema
import LiquidAuthSDK
import LocalAuthentication
import MnemonicSwift
import SwiftCBOR
import x_hd_wallet_api

// MARK: - Example Wallet Implementations

// 📱 These implementations stay in wallet apps as examples
// Each wallet will create their own implementations based on their architecture

/// Example implementation of Liquid Auth challenge signer for this wallet
/// Other wallets should create similar implementations using their own key management
struct ExampleLiquidAuthSigner: LiquidAuthChallengeSigner {
    private let ed25519Wallet: XHDWalletAPI

    init(ed25519Wallet: XHDWalletAPI) {
        self.ed25519Wallet = ed25519Wallet
    }

    func signLiquidAuthChallenge(_ challenge: Data) async throws -> Data {
        Logger.debug("🔐 === CHALLENGE SIGNING STARTED ===")
        Logger.debug("Challenge received: \(challenge.map { String(format: "%02hhx", $0) }.joined())")
        Logger.debug("Challenge size: \(challenge.count) bytes")

        if let schemaPath = Bundle.main.path(forResource: "auth.request", ofType: "json") {
            do {
                let schema = try Schema(filePath: schemaPath)
                let valid = try ed25519Wallet.validateData(data: challenge, metadata: SignMetadata(encoding: .none, schema: schema))
                if valid {
                    Logger.debug("✅ Challenge validation passed")
                } else {
                    Logger.error("❌ Challenge validation failed: Data validation error when signing challenge")
                    throw NSError(domain: "com.liquidauth.error", code: -1,
                                  userInfo: [NSLocalizedDescriptionKey: "Data validation error when signing challenge"])
                }
            } catch {
                Logger.error("❌ Schema validation error: \(error)")
                throw error
            }
        } else {
            Logger.error("❌ Failed to load schema for validation")
            throw NSError(domain: "com.liquidauth.error", code: -2,
                          userInfo: [NSLocalizedDescriptionKey: "Schema for validation is missing or invalid"])
        }

        do {
            let signature = try ed25519Wallet.sign(
                bip44Path: [UInt32(0x8000_0000) + 44, UInt32(0x8000_0000) + 283, UInt32(0x8000_0000) + 0, 0, 0],
                message: challenge,
                derivationType: BIP32DerivationType.Peikert
            )
            Logger.debug("✅ Challenge signature completed: \(signature.map { String(format: "%02hhx", $0) }.joined())")
            Logger.debug("🔐 === CHALLENGE SIGNING COMPLETED ===")
            return signature
        } catch {
            Logger.error("❌ Ed25519 signing failed: \(error)")
            throw error
        }
    }
}

/// Example implementation of message handler for this wallet
struct ExampleMessageHandler: LiquidAuthMessageHandler {
    private let ed25519Wallet: XHDWalletAPI

    init(ed25519Wallet: XHDWalletAPI) {
        self.ed25519Wallet = ed25519Wallet
    }

    func handleMessage(_ message: String) async -> String? {
        Logger.info("📨 Handling incoming message")

        // Try to decode and determine message type
        if isARC27Message(message) {
            return await handleARC27Transaction(message)
        }

        // Handle other message types here in the future
        // e.g., if isOtherMessageType(message) { ... }

        Logger.debug("Unknown message type, ignoring")
        return nil
    }

    private func isARC27Message(_ message: String) -> Bool {
        guard let cborData = Utility.decodeBase64Url(message),
              let cbor = try? CBOR.decode([UInt8](cborData)),
              let dict = cbor.asSwiftObject() as? [String: Any],
              let reference = dict["reference"] as? String
        else {
            return false
        }
        return reference == "arc0027:sign_transactions:request"
    }

    private func handleARC27Transaction(_ message: String) async -> String? {
        // 1. Decode base64url CBOR
        guard let cborData = Utility.decodeBase64Url(message),
              let cbor = try? CBOR.decode([UInt8](cborData)),
              let dict = cbor.asSwiftObject() as? [String: Any]
        else {
            Logger.error("Failed to decode CBOR message")
            return nil
        }

        // 2. Extract ARC27 fields
        guard let reference = dict["reference"] as? String,
              reference == "arc0027:sign_transactions:request",
              let params = dict["params"] as? [String: Any],
              let txns = params["txns"] as? [[String: Any]],
              let requestId = dict["id"] as? String
        else {
            Logger.error("Invalid ARC27 request format")
            return nil
        }

        // 3. Request user approval for transaction signing
        let userApproved = await requestUserApprovalForSigning()
        guard userApproved else {
            Logger.error("User denied transaction signing")
            return nil
        }

        // 4. Sign each transaction with wallet's logic
        var signedTxns: [String] = []
        for txnObj in txns {
            guard let txnBase64Url = txnObj["txn"] as? String,
                  let txnBytes = Utility.decodeBase64Url(txnBase64Url)
            else {
                Logger.error("Failed to decode transaction")
                continue
            }

            // Wallet-specific transaction signing
            if let signature = await signTransaction(txnBytes) {
                signedTxns.append(signature)
            }
        }

        // 5. Build ARC27 response
        let response: [String: Any] = [
            "id": UUID().uuidString,
            "reference": "arc0027:sign_transactions:response",
            "requestId": requestId,
            "result": [
                "providerId": params["providerId"] ?? "liquid-auth-ios-example",
                "stxns": signedTxns,
            ],
        ]

        // 6. Encode and return
        guard let cborResponse = try? CBOR.encodeMap(response) else {
            Logger.error("Failed to encode ARC27 response")
            return nil
        }

        return Data(cborResponse).base64URLEncodedString()
    }

    private func requestUserApprovalForSigning() async -> Bool {
        // Request user verification for transaction signing
        return await requireUserVerification(reason: "Approve transaction signing")
    }

    private func signTransaction(_ txnBytes: Data) async -> String? {
        // Wallet-specific transaction signing logic
        let prefix = Data([0x54, 0x58]) // "TX" prefix for Algorand transactions
        let bytesToSign = prefix + txnBytes

        Logger.debug("Signing transaction: \(bytesToSign.map { String(format: "%02hhx", $0) }.joined())")

        do {
            let signature = try ed25519Wallet.sign(
                bip44Path: [UInt32(0x8000_0000) + 44, UInt32(0x8000_0000) + 283, UInt32(0x8000_0000) + 0, 0, 0],
                message: bytesToSign,
                derivationType: BIP32DerivationType.Peikert
            )
            return signature.base64URLEncodedString()
        } catch {
            Logger.error("Failed to sign transaction: \(error)")
            return nil
        }
    }
}

// MARK: - User Verification Helper

/// Requests user verification using biometric authentication or passcode
func requireUserVerification(reason: String = "Authenticate to continue") async -> Bool {
    Logger.debug("🔐 Starting user verification with reason: \(reason)")

    let context = LAContext()
    var error: NSError?
    let policy: LAPolicy = .deviceOwnerAuthentication // biometrics OR passcode

    // Check what authentication methods are available
    let biometryType = context.biometryType
    Logger.debug("Available biometry type: \(biometryType.rawValue)")

    if context.canEvaluatePolicy(policy, error: &error) {
        Logger.debug("Device can evaluate policy - proceeding with authentication")

        return await withCheckedContinuation { continuation in
            context.evaluatePolicy(policy, localizedReason: reason) { success, authError in
                if success {
                    Logger.debug("✅ User verification successful")
                    continuation.resume(returning: true)
                } else {
                    if let authError = authError {
                        Logger.error("❌ User verification failed: \(authError.localizedDescription)")
                    } else {
                        Logger.error("❌ User verification failed with unknown error")
                    }
                    continuation.resume(returning: false)
                }
            }
        }
    } else {
        // Device does not support biometrics/passcode
        if let error = error {
            Logger.error("❌ Device cannot evaluate authentication policy: \(error.localizedDescription)")
        } else {
            Logger.error("❌ Device does not support biometrics/passcode authentication")
        }
        return false
    }
}

// MARK: - Wallet Information

struct WalletInfo {
    let ed25519Wallet: XHDWalletAPI
    let dp256: DeterministicP256
    let derivedMainKey: Data
    let p256KeyPair: P256.Signing.PrivateKey
    let address: String

    func createChallengeSigner() -> LiquidAuthChallengeSigner {
        return ExampleLiquidAuthSigner(ed25519Wallet: ed25519Wallet)
    }

    func createMessageHandler() -> LiquidAuthMessageHandler {
        return ExampleMessageHandler(ed25519Wallet: ed25519Wallet)
    }
}

/// Encode an Ed25519 public key into an Algorand Base32 address with checksum
///
/// - Parameter bytes: The Ed25519 public key bytes
/// - Returns: Base32 encoded Algorand address string
/// - Throws: NSError if the address length is unexpected
func encodeAddress(bytes: Data) throws -> String {
    let lenBytes = 32
    let checksumLenBytes = 4
    let expectedStrEncodedLen = 58

    // compute sha512/256 checksum
    let hash = Data(SHA512_256().hash([UInt8](bytes)))
    let hashedAddr = hash[..<lenBytes] // Take the first 32 bytes

    // take the last 4 bytes of the hashed address, and append to original bytes
    let checksum = hashedAddr[(hashedAddr.count - checksumLenBytes)...]
    let checksumAddr = bytes + checksum

    // encodeToMsgPack addr+checksum as base32 and return. Strip padding.
    let res = base32Encode(checksumAddr).trimmingCharacters(in: ["="])
    if res.count != expectedStrEncodedLen {
        throw NSError(
            domain: "",
            code: 0,
            userInfo: [NSLocalizedDescriptionKey: "unexpected address length \(res.count)"]
        )
    }
    return res
}

func getWalletInfo(origin: String) throws -> WalletInfo {
    let phrase = "youth clog use limit else hub select cause digital oven stand bike alarm ring phone remain trigger essay royal tortoise bless goose forum reflect"
    let seed = try Mnemonic.deterministicSeedString(from: phrase)
    guard let ed25519Wallet = XHDWalletAPI(seed: seed) else {
        throw NSError(domain: "Wallet creation failed", code: -1, userInfo: nil)
    }

    let pk = try ed25519Wallet.keyGen(context: KeyContext.Address, account: 0, change: 0, keyIndex: 0)
    let address = try encodeAddress(bytes: pk)

    let dp256 = DeterministicP256()
    let derivedMainKey = try dp256.genDerivedMainKeyWithBIP39(phrase: phrase)
    let p256KeyPair = dp256.genDomainSpecificKeyPair(derivedMainKey: derivedMainKey, origin: origin, userHandle: address)

    return WalletInfo(
        ed25519Wallet: ed25519Wallet,
        dp256: dp256,
        derivedMainKey: derivedMainKey,
        p256KeyPair: p256KeyPair,
        address: address
    )
}
