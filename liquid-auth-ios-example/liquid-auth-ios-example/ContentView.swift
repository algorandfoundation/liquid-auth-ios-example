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
import AVFoundation
import ExampleShared
import LiquidAuthSDK
import SwiftUI

struct ContentView: View {
    @State private var isScanning = false
    @State private var isLoading = false
    @State private var scannedMessage: String? = nil
    @State private var errorMessage: String? = nil

    @State private var showActionSheet = false
    @State private var actionSheetOrigin: String?
    @State private var actionSheetRequestId: String?

    @State private var algorandAddress: String? = nil
    @State private var showCopyConfirmation = false

    var body: some View {
        ZStack {
            NavigationStack {
                VStack {
                    Image(systemName: "globe")
                        .imageScale(.large)
                        .foregroundStyle(.tint)
                    Text("Ready to scan?")

                    if let address = algorandAddress {
                        Text("Algorand Address:")
                            .font(.headline)
                            .padding(.top, 8)
                        HStack(spacing: 8) {
                            Text("\(address.prefix(6))...\(address.suffix(6))")
                                .font(.system(.footnote, design: .monospaced))
                                .lineLimit(1)
                                .truncationMode(.middle)
                            Button(action: {
                                UIPasteboard.general.string = address
                                showCopyConfirmation = true
                            }) {
                                Image(systemName: "doc.on.doc")
                                    .foregroundColor(.blue)
                            }
                            .buttonStyle(.borderless)
                            .accessibilityLabel("Copy address")
                        }
                        .padding(.bottom, 8)
                        if showCopyConfirmation {
                            Text("Copied!")
                                .font(.caption)
                                .foregroundColor(.green)
                                .transition(.opacity)
                        }
                    } else {
                        ProgressView("Generating address...")
                            .padding(.vertical, 8)
                    }

                    Button(action: {
                        isScanning = true
                    }) {
                        Text("Scan QR Code")
                            .padding()
                            .background(Color.blue)
                            .foregroundColor(.white)
                            .cornerRadius(8)
                    }
                    .navigationDestination(isPresented: $isScanning) {
                        QRCodeScannerView { scannedCode in
                            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                                handleScannedCode(scannedCode)
                            }
                        }
                    }

                    if let message = scannedMessage {
                        ScrollView {
                            Text("Message: \(message)")
                                .padding()
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                        .frame(maxHeight: 300)
                        .padding()
                    }

                    if let error = errorMessage {
                        Text("Error: \(error)")
                            .foregroundColor(.red)
                            .padding()
                    }
                }
                .padding()
                .actionSheet(isPresented: $showActionSheet) {
                    actionSheet
                }
                .navigationTitle("Liquid Auth")
                .onAppear {
                    // Generate Algorand address once when view appears
                    if algorandAddress == nil {
                        Task {
                            do {
                                let walletInfo = try getWalletInfo(origin: "liquid-auth-example")
                                DispatchQueue.main.async {
                                    self.algorandAddress = walletInfo.address
                                }
                            } catch {
                                DispatchQueue.main.async {
                                    self.algorandAddress = "Error generating address"
                                }
                            }
                        }
                    }
                }
                .onDisappear {
                    // Reset state when navigating back
                    resetState()
                }
            }

            // Show the processing pop-up only when isLoading is true
            if isLoading {
                VStack {
                    ProgressView("Processing...")
                        .padding()
                        .background(Color.black)
                        .cornerRadius(10)
                        .shadow(radius: 10)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
                .background(Color.black.opacity(0.5))
                .edgesIgnoringSafeArea(.all)
            }
        }
    }

    private var actionSheet: ActionSheet {
        ActionSheet(
            title: Text("Choose Action"),
            message: Text("Would you like to register or authenticate?"),
            buttons: [
                .default(Text("Register")) {
                    startProcessing {
                        Task {
                            if let origin = actionSheetOrigin, let requestId = actionSheetRequestId {
                                defer { isLoading = false }
                                do {
                                    let state = await ASCredentialIdentityStore.shared.state()
                                    if !state.isEnabled {
                                        Logger.warning("AutoFill is not enabled")

                                        DispatchQueue.main.async {
                                            self.scannedMessage = nil
                                            self.errorMessage = "AutoFill Passwords & Passkeys is not enabled for Liquid Auth. Please enable it in Settings > General > AutoFill & Passwords."
                                        }
                                        return
                                    }
                                    let userVerified = await requireUserVerification(reason: "Authenticate to register with Liquid Auth")
                                    guard userVerified else {
                                        Logger.error("❌ User verification failed")
                                        DispatchQueue.main.async {
                                            self.scannedMessage = nil
                                            self.errorMessage = "User verification is required for this action"
                                        }
                                        return
                                    }
                                    let walletInfo = try getWalletInfo(origin: origin)
                                    let challengeSigner = walletInfo.createChallengeSigner()
                                    let messageHandler = walletInfo.createMessageHandler()
                                    let deviceInfo = getDeviceInformation()
                                    let client = LiquidAuthClient()
                                    let result = try await client.register(
                                        origin: origin,
                                        requestId: requestId,
                                        algorandAddress: walletInfo.address,
                                        challengeSigner: challengeSigner,
                                        p256KeyPair: walletInfo.p256KeyPair,
                                        messageHandler: messageHandler,
                                        userAgent: deviceInfo.userAgent,
                                        device: deviceInfo.device
                                    )
                                    DispatchQueue.main.async {
                                        if result.success {
                                            self.scannedMessage = "Registration completed successfully."
                                            self.errorMessage = nil
                                        } else {
                                            self.scannedMessage = nil
                                            self.errorMessage = result.errorMessage
                                        }
                                    }
                                } catch {
                                    Logger.error("❌ Error in LiquidAuth register: \(error)")
                                    DispatchQueue.main.async {
                                        self.errorMessage = "Failed to complete Liquid Auth registration: \(error.localizedDescription)"
                                        self.scannedMessage = nil
                                    }
                                }
                            }
                        }
                    }
                },
                .default(Text("Authenticate")) {
                    startProcessing {
                        Task {
                            if let origin = actionSheetOrigin, let requestId = actionSheetRequestId {
                                defer { isLoading = false }
                                do {
                                    let userVerified = await requireUserVerification(reason: "Authenticate to sign in with Liquid Auth")
                                    guard userVerified else {
                                        Logger.error("❌ User verification failed")
                                        DispatchQueue.main.async {
                                            self.scannedMessage = nil
                                            self.errorMessage = "User verification is required for this action"
                                        }
                                        return
                                    }
                                    let walletInfo = try getWalletInfo(origin: origin)
                                    let challengeSigner = walletInfo.createChallengeSigner()
                                    let messageHandler = walletInfo.createMessageHandler()
                                    let deviceInfo = getDeviceInformation()
                                    let client = LiquidAuthClient()
                                    let result = try await client.authenticate(
                                        origin: origin,
                                        requestId: requestId,
                                        algorandAddress: walletInfo.address,
                                        challengeSigner: challengeSigner,
                                        p256KeyPair: walletInfo.p256KeyPair,
                                        messageHandler: messageHandler,
                                        userAgent: deviceInfo.userAgent,
                                        device: deviceInfo.device
                                    )
                                    DispatchQueue.main.async {
                                        if result.success {
                                            self.scannedMessage = "Authentication completed successfully."
                                            self.errorMessage = nil
                                        } else {
                                            self.scannedMessage = nil
                                            self.errorMessage = result.errorMessage
                                        }
                                    }
                                } catch {
                                    Logger.error("❌ Error in LiquidAuth authenticate: \(error)")
                                    DispatchQueue.main.async {
                                        self.errorMessage = "Failed to complete Liquid Auth authentication: \(error.localizedDescription)"
                                        self.scannedMessage = nil
                                    }
                                }
                            }
                        }
                    }
                },
                .cancel {
                    resetState() // Reset state when "Cancel" is pressed
                },
            ]
        )
    }

    private func resetState() {
        // Reset all states
        isLoading = false
        scannedMessage = nil
        errorMessage = nil
        showActionSheet = false
        actionSheetOrigin = nil
        actionSheetRequestId = nil
    }

    private func handleScannedCode(_ code: String) {
        isScanning = false // Dismiss the QR code scanner
        isLoading = false // Ensure progress bar is hidden
        showActionSheet = false // Ensure action sheet is hidden

        if code.starts(with: "FIDO:/") {
            showFIDOAlert()
        } else if code.starts(with: "liquid://") {
            // Handle Liquid Auth URI
            isLoading = true
            handleLiquidAuthURI(code)
        } else {
            Logger.error("Unsupported QR code format: \(code)")
            errorMessage = "Unsupported QR code format."
            scannedMessage = nil
        }
    }

    private func showFIDOAlert() {
        let alert = UIAlertController(
            title: "Scan with Camera App",
            message: "This is a FIDO:/ QR Code. Please scan this QR code using the iPhone Camera app.",
            preferredStyle: .alert
        )
        alert.addAction(UIAlertAction(title: "OK", style: .default, handler: nil))
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let rootVC = windowScene.windows.first?.rootViewController
        {
            rootVC.present(alert, animated: true, completion: nil)
        }
    }

    private func handleLiquidAuthURI(_ uri: String) {
        Task {
            // Update the UI to show the scanned message
            scannedMessage = "Liquid Auth URI: \(uri)"
            errorMessage = nil
            Logger.debug("Handling Liquid Auth URI: \(uri)")

            // Extract origin and request ID from the URI
            guard let (origin, requestId) = Utility.extractOriginAndRequestId(from: uri) else {
                Logger.error("Failed to extract origin and request ID.")
                errorMessage = "Invalid Liquid Auth URI."
                isLoading = false
                return
            }

            Logger.debug("Origin: \(origin), Request ID: \(requestId)")

            // Prompt the user to choose between registration and authentication
            DispatchQueue.main.async {
                actionSheetOrigin = origin
                actionSheetRequestId = requestId
                showActionSheet = true
            }
        }
    }

    private func getDeviceInformation() -> (userAgent: String, device: String) {
        let appName = Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String ?? "UnknownApp"
        let appVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "UnknownVersion"
        let deviceModel = UIDevice.current.model
        let systemName = UIDevice.current.systemName
        let systemVersion = UIDevice.current.systemVersion

        let userAgent = "\(appName)/\(appVersion) (\(deviceModel); \(systemName) \(systemVersion))"
        let device = deviceModel // e.g., "iPhone", "iPad"

        return (userAgent: userAgent, device: device)
    }

    private func startProcessing(action: @escaping () -> Void) {
        // Ensure the progress bar only shows after the action sheet is dismissed
        showActionSheet = false
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) {
            isLoading = true
            action()
        }
    }
}

#Preview {
    ContentView()
}
