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

public class CredentialsJWT<C: Claims>: CredentialsPluginProtocol {
    
    public var usersCache: NSCache<NSString, BaseCacheElement>?
    
    public var name: String {
        return "JWT"
    }
    
    public var redirecting: Bool {
        return false
    }
    
    /// The time in seconds since the user profile was generated that the access token will be considered valid.
    public let tokenTimeToLive: TimeInterval?
    
    private var delegate: UserProfileDelegate?
    
    private let subjectClaim: String
    
    private let verifier: JWTVerifier
    
    var token = ""
    
    public var userProfileDelegate: UserProfileDelegate? {
        return delegate
    }
    
    /// Initialize a `CredentialsGoogleToken` instance.
    ///
    /// - Parameter options: A dictionary of plugin specific options. The keys are defined in `CredentialsGoogleOptions`.
    public init(verifier: JWTVerifier, options: [String:Any]?=nil, tokenTimeToLive: TimeInterval? = nil) {
        self.verifier = verifier
        delegate = options?[CredentialsJWTOptions.userProfileDelegate] as? UserProfileDelegate
        subjectClaim = options?[CredentialsJWTOptions.subject] as? String ?? "sub"
        self.tokenTimeToLive = tokenTimeToLive
    }
    
    public func authenticate(request: RouterRequest, response: RouterResponse,
                            options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                            onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                            onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                            inProgress: @escaping () -> Void) {
        
        if let type = request.headers["X-token-type"], type == name {
            if let rawToken = request.headers["Authorization"] {
                // TODO: Strip bearer from start if present
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
                
                let jwt = try? JWT<C>(jwtString: token, verifier: verifier)

                // TODO: Finish this implementation
            }
            
        }
    }
    
}
