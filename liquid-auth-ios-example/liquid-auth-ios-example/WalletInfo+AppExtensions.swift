import ExampleShared
import Foundation

public extension WalletInfo {
  func createChallengeSigner() -> LiquidAuthChallengeSigner {
    return ExampleLiquidAuthSigner(ed25519Wallet: ed25519Wallet)
  }

  func createMessageHandler() -> LiquidAuthMessageHandler {
    return ExampleMessageHandler(ed25519Wallet: ed25519Wallet)
  }
}
