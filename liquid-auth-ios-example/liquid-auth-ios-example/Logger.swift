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
