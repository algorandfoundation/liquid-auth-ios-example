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

// MARK: - Utility

public enum Utility {
    /// Extracts the origin and request ID from a Liquid Auth URI
    ///
    /// - Parameter uri: The liquid:// URI to parse
    /// - Returns: A tuple containing the origin and requestId, or nil if parsing fails
    public static func extractOriginAndRequestId(from uri: String) -> (origin: String, requestId: String)? {
        guard let url = URL(string: uri),
              url.scheme == "liquid",
              let host = url.host,
              let queryItems = URLComponents(string: uri)?.queryItems,
              let requestId = queryItems.first(where: { $0.name == "requestId" })?.value
        else {
            return nil
        }
        return (origin: host, requestId: requestId)
    }

    /// Decodes a Base64URL string into bytes
    ///
    /// - Parameter base64Url: The Base64URL encoded string
    /// - Returns: Decoded data, or nil if decoding fails
    public static func decodeBase64Url(_ base64Url: String) -> Data? {
        // Replace Base64Url characters with Base64 equivalents
        var base64 = base64Url
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        // Add padding if necessary
        let paddingLength = 4 - (base64.count % 4)
        if paddingLength < 4 {
            base64.append(String(repeating: "=", count: paddingLength))
        }

        // Decode the Base64 string
        return Data(base64Encoded: base64)
    }

    /// Decodes a Base64URL string into a JSON representation of bytes
    ///
    /// - Parameter base64Url: The Base64URL encoded string
    /// - Returns: JSON string representation of bytes, or nil if decoding fails
    public static func decodeBase64UrlToJSON(_ base64Url: String) -> String? {
        // Decode the Base64Url string into Data
        guard let decodedData = decodeBase64Url(base64Url) else {
            return nil
        }

        // Convert Data to [UInt8]
        let decodedBytes = [UInt8](decodedData)

        // Create a dictionary where each byte is represented as a key-value pair
        let byteDictionary = decodedBytes.enumerated().reduce(into: [String: UInt8]()) { dict, pair in
            dict["\(pair.offset)"] = pair.element
        }

        // Convert the dictionary to a JSON string
        if let jsonData = try? JSONSerialization.data(withJSONObject: byteDictionary, options: [.prettyPrinted]),
           let jsonString = String(data: jsonData, encoding: .utf8)
        {
            return jsonString
        }

        return nil
    }
}
