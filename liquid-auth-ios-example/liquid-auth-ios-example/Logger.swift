import Foundation

enum LogLevel: Int {
    case error = 0
    case warning = 1
    case info = 2
    case debug = 3
}

public class Logger {
    static var currentLevel: LogLevel = .info

    static func error(_ message: String) {
        if currentLevel.rawValue >= LogLevel.error.rawValue {
            print("❌ [ERROR] \(message)")
        }
    }

    static func warning(_ message: String) {
        if currentLevel.rawValue >= LogLevel.warning.rawValue {
            print("⚠️ [WARNING] \(message)")
        }
    }

    static func info(_ message: String) {
        if currentLevel.rawValue >= LogLevel.info.rawValue {
            print("ℹ️ [INFO] \(message)")
        }
    }

    static func debug(_ message: String) {
        if currentLevel.rawValue >= LogLevel.debug.rawValue {
            print("🐞 [DEBUG] \(message)")
        }
    }
}
