# Liquid Auth iOS Example App
Welcome to the Example app and extension showcasing Liquid Auth iOS (LiquidAuthSDK).

## Structure

The example app has a main app, whose entrypoint is `liquid-auth-ios-example/ContentView.swift`. The main app comes with a QR code scanner, which can be used to scan `liquid://` URI QR codes. From there the Liquid Auth SDK is used to handle registering and authenticating against a Liquid Auth backend, followed by the creation of the WebRTC data channel. Once the data channel has been setup, data (such as transaction bytes to be signed) can be communicated over.

The extension, whose entrypoint is `AutofillCredentialExtension/CredentialProviderViewController.swift`, contains code and permissions allowing the app to be listed as a (potential) Passkey Manager under `Settings/General/Autofill & Passwords`. It implements `ASCredentialProviderViewController` and overrides key methods, such as `prepareInterface` and `prepareCredentialList`. As a result, the user can open up the standard iPhone Camera App, scan a `FIDO:/` URI QR code (e.g., at [webauthn.io](https://webauthn.io) for testing) and have the app pop up as an alternative for registering and authenticating with passkeys.