//
//  GPhotos.swift
//  GPhotos
//
//  Created by Deivi Taka on 19.08.19.
//  Copyright © 2019 Deivi Taka. All rights reserved.
//

import UIKit
import GTMAppAuth
import AppAuth
import GTMSessionFetcher

public class GPhotos {
    
    internal static var currentAuthFlow: OIDExternalUserAgentSession?
    internal static var authState: OIDAuthState?
    internal static var configuration: OIDServiceConfiguration?
    internal static var fetcherService = GTMSessionFetcherService()

    internal static var initialized = false
    
    /// Will return true if a user is already authorized. Check before calling GPhotos.authorize(), unless you want to switch users, or add new scopes.
    public static var isAuthorized: Bool { get {
        return !Strings.photosAccessToken.isEmpty
    }}
    
    // MARK:- Basic functions
    
    public static func initialize(with configuration: Config? = nil) {
        if let configuration = configuration {
            config.printLogs = configuration.printLogs
        }
        
        // Load authorization from keychain
        if let authStateData = KeychainManager.load(forKey: Strings.keychainName),
           let state = try? NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: authStateData) {
            self.authState = state
        } else {
            print("No authorization found in keychain")
        }

        self.configuration = AuthSession.configurationForGoogle()
        initialized = true
        
        refreshToken()
    }
    
    /// By default starts the authentication process with openid scope. As per Google recommendation, you should gradually add scopes when you need to use them, not on the first run. The method will return a boolean indicating the success status, and an error if any.
    public static func authorize(with scopes: Set<AuthScope> = [.openId], completion: ((Bool, Error?)->())? = nil) {
        authorize(with: scopes, filterScopes: true, completion: completion)
    }
    
    /// By default starts the authentication process with openid scope. Will ignore current authentication scopes. The method will return a boolean indicating the success status, and an error if any.
    public static func switchAccount(with scopes: Set<AuthScope> = [.openId], completion: ((Bool, Error?)->())? = nil) {
        authorize(with: scopes, filterScopes: false, completion: completion)
    }
    
    /// Handles redirects during the authorization process
    public static func continueAuthorizationFlow(with url: URL) -> Bool {
        validate()
        
        // Sends the URL to the current authorization flow (if any) which will
        // process it if it relates to an authorization response.
        if let currentAuthFlow = currentAuthFlow,
            currentAuthFlow.resumeExternalUserAgentFlow(with: url) {
            self.currentAuthFlow = nil
            return true
        }
        return false
    }
    
    /// Clears the session information and invalidates any token saved.
    public static func logout() {
        validate()
        currentAuthFlow = nil
        authState = nil
        KeychainManager.delete(forKey: Strings.keychainName)
        print("Authorization state removed from keychain")    }
}

// MARK:- Internal functions
internal extension GPhotos {
    
    static func validate() {
        guard initialized else {
            fatalError("'GPhotos.config()' has not been called")
        }
        
        guard !Google.plistDict.allValues.isEmpty else {
            fatalError("Could not load GoogleService-Info.plist. Please make sure it is added to the project.")
        }
        
        guard topVC != nil else {
            fatalError("Could not find a view controller. Please make sure you are not calling from 'viewDidLoad' on the first View Controller.")
        }
    }
    
    static func refreshTokenIfNeeded(completion: (()->())? = nil) {
        // Do a dummy call and GTMSessionFetcherService will take care of refreshing the token
        background {
            let now = Date().timeIntervalSinceReferenceDate
            let lastChecked = defaults.double(forKey: Strings.lastTokenRefresh)
            // Don't check within t minutes to avoid making unnecessary network calls
            if Int(now - lastChecked) < config.refreshTokenTimeout {
                completion?()
                return
            }
            refreshToken(completion: completion)
        }
    }
    
    static func refreshToken(completion: (()->())? = nil) {
        // Do a dummy call and GTMSessionFetcherService will take care of refreshing the token
        background {
            guard let authState = self.authState else {
                log.e("Authorization state is nil.")
                completion?()
                return
            }
            if let tokenEndpoint = self.configuration?.tokenEndpoint {
                let fetcher = self.fetcherService.fetcher(with: tokenEndpoint)
                fetcher.beginFetch(completionHandler: { (data, error) in
                    if let error = error as NSError?,
                       error.domain == OIDOAuthTokenErrorDomain {
                        log.e("Authorization error during token refresh.")
                        self.authState = nil
                    }

                    defaults.setValue(Date().timeIntervalSinceReferenceDate,
                                      forKey: Strings.lastTokenRefresh)
                    completion?()
                })
            }
            else { completion?() }
        }
    }
    
    static func checkScopes(with scopes: [AuthScope], required: Bool) -> Bool {
        if !Google.currentScopes.contains(where: { scopes.contains($0)}) {
            let scopes = scopes.map({ String(describing: $0) })
            let message = "Need to authorize with one of the scopes: \(scopes)"
            if required {
                log.e(message)
            } else {
                log.w(message)
            }
            return false
        }
        return true
    }
}

fileprivate extension GPhotos {
    
    static func filter(_ scopes: Set<AuthScope>) -> Set<AuthScope> {
        var scopes = scopes
        var currentScopes = Google.currentScopes
        while !currentScopes.isEmpty {
            let scope = currentScopes.removeFirst()
            if let index = scopes.firstIndex(where: { $0 == scope }) {
                scopes.remove(at: index)
            }
        }
        return scopes
    }
    
    static func authorize(with scopes: Set<AuthScope> = [.openId], filterScopes: Bool, completion: ((Bool, Error?)->())? = nil) {
        validate()
        
        var success = false
        let redirectUrl = Google.urls.redirect!
        var scopes = scopes
        scopes.insert(.openId)
        
        if filterScopes {
            // Will not lose current scopes that are authorized
            let newScopes = self.filter(scopes)
            if newScopes.isEmpty {
                // All scopes are authorized, do nothing
                completion?(true, nil)
                return
            } else {
                // Some scopes are not authorized,
                // request them all again
                Google.currentScopes.forEach({ scopes.insert($0) })
            }
        }
        
        let request = OIDAuthorizationRequest(configuration: configuration!,
                                              clientId: Google.info.clientId,
                                              scopes: scopes.map({ $0.rawValue }),
                                              redirectURL: redirectUrl,
                                              responseType: OIDResponseTypeCode,
                                              additionalParameters: [:])
        
        main {
            currentAuthFlow = OIDAuthState.authState(byPresenting: request, presenting: topVC!) { (state, error) in
                guard let state = state else {
                    self.authState = nil
                    completion?(false, error)
                    return
                }

                // Save the state locally
                self.authState = state

                // Store the state in the keychain
                if let authStateData = try? NSKeyedArchiver.archivedData(withRootObject: state, requiringSecureCoding: false) {
                    KeychainManager.save(data: authStateData, forKey: Strings.keychainName)
                    UserDefaults.standard.setValue(Date().timeIntervalSinceReferenceDate, forKey: Strings.lastTokenRefresh)
                    completion?(true, nil)
                } else {
                    log.e("Failed to archive auth state")
                    completion?(false, nil)
                }
            }
        }

    }
}
