//
//  KeychainManager.swift
//  Pods
//
//  Created by Sayali Deopurkar on 28/01/2025.
//

import Foundation
import Security

final class KeychainManager {
    /// Save data to Keychain
    static func save(data: Data, forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        // Remove existing item if it exists
        SecItemDelete(query as CFDictionary)
        // Add new item to Keychain
        let status = SecItemAdd(query as CFDictionary, nil)
        if status != errSecSuccess {
            print("Keychain Save Error: \(status)")
        }
    }
    
    /// Load data from Keychain
    static func load(forKey key: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecSuccess {
            return result as? Data
        } else {
            print("Keychain Load Error: \(status)")
            return nil
        }
    }
    
    // Delete data from the keychain
    static func delete(forKey key: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]
        SecItemDelete(query as CFDictionary)
    }
}
