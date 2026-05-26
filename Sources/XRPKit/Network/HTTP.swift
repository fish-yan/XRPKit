//
//  File.swift
//  
//
//  Created by Mitch Lang on 1/30/20.
//

import Foundation
#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif
#if canImport(CoreFoundation)
    import CoreFoundation
#endif

class HTTP {
    
    // http call to test linux cross platform
    static func post(url: URL, parameters: [String: Any]) async throws -> Any {
        let httpBody = try JSONSerialization.data(withJSONObject: parameters, options: [])
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("Application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = httpBody

        let session = URLSession.shared
        let data = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<Data, Error>) in
            session.dataTask(with: request) { data, _, error in
                if let error = error {
                    continuation.resume(throwing: error)
                    return
                }
                if let data = data {
                    continuation.resume(returning: data)
                    return
                }
                continuation.resume(throwing: URLError(.badServerResponse))
            }.resume()
        }

        return try JSONSerialization.jsonObject(with: data, options: [])
    }
}
