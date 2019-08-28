/**
 * Copyright IBM Corporation 2019
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

import Kitura
import KituraNet
import Credentials
import SwiftJWT
import Foundation
import LoggerAPI

// MARK CredentialsJWT

/// Authentication using a JWT.
public class CredentialsJWT<C: Claims>: CredentialsPluginProtocol {
    
    /// The name of the plugin.
    public var name: String {
        return "JWT"
    }
    
    /// An indication as to whether the plugin is redirecting or not.
    public var redirecting: Bool {
        return false
    }
    
    /// The time in seconds since the user profile was generated that the access token will be considered valid.
    public let tokenTimeToLive: TimeInterval?
    
    private var delegate: UserProfileDelegate?
    
    /// Default sub value used in JWT.
    private let subject: String
    
    /// User supplies a verifier.
    private let verifier: JWTVerifier
    
    /// Token variable used after formatting.
    var token = ""
    
    /// A delegate for `UserProfile` manipulation.
    public var userProfileDelegate: UserProfileDelegate? {
        return delegate
    }
    
    /// Initialize a `CredentialsJWT` instance.
    ///
    /// - Parameter options: A dictionary of plugin specific options. The keys are defined in `CredentialsJWTOptions`.
    public init(verifier: JWTVerifier, options: [String:Any]?=nil, tokenTimeToLive: TimeInterval? = nil) {
        self.verifier = verifier
        delegate = options?[CredentialsJWTOptions.userProfileDelegate] as? UserProfileDelegate
        subject = options?[CredentialsJWTOptions.subject] as? String ?? "sub"
        self.tokenTimeToLive = tokenTimeToLive
    }
    
    /// User profile cache.
    public var usersCache: NSCache<NSString, BaseCacheElement>?
    
    /// Authenticate incoming request using a JWT.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter options: The dictionary of plugin specific options.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication token in the request.
    /// - Parameter inProgress: The closure to invoke to cause a redirect to the login page in the
    ///                     case of redirecting authentication.
    public func authenticate(request: RouterRequest, response: RouterResponse,
                            options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                            onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                            onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                            inProgress: @escaping () -> Void) {
        
        if let type = request.headers["X-token-type"], type == name {
            if let rawToken = request.headers["Authorization"] {
                if rawToken.hasPrefix("Bearer") {
                    let rawTokenParts = rawToken.split(separator: " ", maxSplits: 2)
                    token = String(rawTokenParts[1])
                }
                else {
                    token = rawToken
                }
                #if os(Linux)
                    let key = NSString(string: token)
                #else
                    let key = token as NSString
                #endif
                if let cached = usersCache?.object(forKey: key) {
                    if let ttl = tokenTimeToLive {
                        if Date() < cached.createdAt.addingTimeInterval(ttl) {
                            onSuccess(cached.userProfile)
                            return
                        }
                        // If current time is later than time to live, continue to standard token authentication.
                        // Don't need to evict token, since it will replaced if the token is successfully autheticated.
                    } else {
                        // No time to live set, use token until it is evicted from the cache
                        onSuccess(cached.userProfile)
                        return
                    }
                    
                }
                
                do {
                    _ = try JWT<C>(jwtString: token, verifier: verifier)
                    
                    let components = token.components(separatedBy: ".")
                    guard components.count == 2 || components.count == 3,
                        let claimsData = Data(base64urlEncoded: components[1]),
                        let dictionary = try? JSONSerialization.jsonObject(with: claimsData, options: []) as? [String:Any]
                        else {
                            Log.info("Couldn't decode claims")
                            return onFailure(nil, nil)
                    }
                    guard let userid = dictionary[subject] as? String else {
                        Log.info("JWT claims dont contain subject")
                        return onFailure(nil, nil)
                    }
                    
                    let userProfile = UserProfile(id: userid , displayName: userid, provider: "JWT")
                    
                    delegate?.update(userProfile: userProfile, from: dictionary)
                    
                    let newCacheElement = BaseCacheElement(profile: userProfile)
        
                    self.usersCache?.setObject(newCacheElement, forKey: key)
                    onSuccess(userProfile)
                } catch {
                    Log.info("JWT can't be verified: \(error)")
                    onFailure(nil, nil)
                }
                
            } else {
                //No Authorization header
                Log.info("Bad authorization header")
                onFailure(nil, nil)
            }
            
        } else {
            //Not JWT
            Log.info("Wasn't a JWT")
            onPass(nil, nil)
            
        }
    }
    
}

extension Data {
    func base64urlEncodedString() -> String {
        let result = self.base64EncodedString()
        return result.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
    
    init?(base64urlEncoded: String) {
        let paddingLength = 4 - base64urlEncoded.count % 4
        let padding = (paddingLength < 4) ? String(repeating: "=", count: paddingLength) : ""
        let base64EncodedString = base64urlEncoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            + padding
        self.init(base64Encoded: base64EncodedString)
    }
}
