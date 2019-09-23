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

/**
 A plugin for Kitura-Credentials supporting authentication using [JSON Web Tokens](https://jwt.io/).

 This plugin requires that the following HTTP headers are present on a request:
 - `Authorization`: the JWT string, optionally prefixed with `Bearer`

 If you wish to use multiple Credentials plugins, then additionally the header:
 - `X-token-type`: must equal `JWT`.

 The [Swift-JWT](https://github.com/IBM-Swift/Swift-JWT) library is used to
 decode JWT strings. To successfully decode it, you must specify the `Claims` that will
 be present in the JWT.  One claim (by default, `sub`) will be used to represent the identity of
 the bearer.  You can choose a different claim by supplying the `subject` option when
 creating an instance of CredentialsJWT, and you can further customize the resulting `UserProfile`
 by defining a `UserProfileDelegate`.

 ### Usage Example

 To use `CredentialsJWT` using the default options:
 ```swift
 import Credentials
 import CredentialsJWT
 import SwiftJWT

 // Defines the claims that must be present in a JWT.
 struct MyClaims: Claims {
     let sub: String
 }

 // Defines the method used to verify the signature of a JWT.
 let jwtVerifier = .hs256(key: "<PrivateKey>".data(using: .utf8)!)

 // Create a CredentialsJWT plugin with default options.
 let jwtCredentials = CredentialsJWT<MyClaims>(verifier: jwtVerifier)

 let authenticationMiddleware = Credentials()
 authenticationMiddleware.register(plugin: jwtCredentials)
 router.get("/myProtectedRoute", middleware: authenticationMiddleware)
 ```

 Following successful authentication, the `UserProfile` will be minimally populated with the
 two required fields - `id` and `displayName` - both with the value of the JWT's `sub` claim.
 The `provider` will be set to `JWT`.

 ### Usage Example - custom claims

 To customize the name of the identity claim, and further populate the UserProfile fields,
 specify the `subject` and `userProfileDelegate` options as follows:
 ```swift
 import Credentials
 import CredentialsJWT
 import SwiftJWT

 // Defines the claims that must be present in a JWT.
 struct MyClaims: Claims {
     let id: Int
     let fullName: String
     let email: String
 }

 struct MyDelegate: UserProfileDelegate {
     func update(userProfile: UserProfile, from dictionary: [String:Any]) {
         // `userProfile.id` already contains `id`
         userProfile.displayName = dictionary["fullName"]! as! String
         let email = UserProfile.UserProfileEmail(value: dictionary["email"]! as! String, type: "home")
         userProfile.emails = [email]
     }
 }

 // Defines the method used to verify the signature of a JWT.
 let jwtVerifier = .hs256(key: "<PrivateKey>".data(using: .utf8)!)

 // Create a CredentialsJWT plugin with default options.
 let jwtCredentials = CredentialsJWT<MyClaims>(verifier: jwtVerifier, options: [CredentialsJWTOptions.subject: "id", CredentialsJWTOptions.userProfileDelegate: MyDelegate])

 let authenticationMiddleware = Credentials()
 authenticationMiddleware.register(plugin: jwtCredentials)
 router.get("/myProtectedRoute", middleware: authenticationMiddleware)
 ```
 Following successful authentication, the `UserProfile` will be populated as follows:
 - `id`: the `id` claim (converted to a String),
 - `displayName`: the `fullName` claim,
 - `emails`: an array with a single element, representing the `email` claim.
*/
public class CredentialsJWT<C: Claims>: CredentialsPluginProtocol {
    
    /// The name of the plugin: `JWT`.
    public var name: String {
        return "JWT"
    }
    
    /// An indication as to whether the plugin is redirecting or not.  This plugin is not redirecting.
    public var redirecting: Bool {
        return false
    }
    
    /// The time in seconds since the user profile was generated that the access token will be considered valid
    /// and remain in the `usersCache`.
    ///
    /// By default, this value is `nil`, which means that tokens will be cached indefinitely.
    public let tokenTimeToLive: TimeInterval?
    
    private var delegate: UserProfileDelegate?
    
    /// Default sub value used in JWT.
    private let subject: String
    
    /// User supplies a verifier.
    private let verifier: JWTVerifier
    
    /// Token variable used after formatting.
    var token = ""
    
    /// A delegate for `UserProfile` manipulation. Use this to further populate the profile using
    /// any fields from the `Claims` that you have defined.
    ///
    /// This field can be set by passing the `userProfileDelegate` option during initialization.
    public var userProfileDelegate: UserProfileDelegate? {
        return delegate
    }
    
    /// Initialize a `CredentialsJWT` instance.  Upon first receipt, a JWT will be verified to ensure the signature is valid,
    /// and that the JWT's claims can be decoded into an instance of your `Claims` type. The claims are used to generate
    /// a `UserProfile`.  The profile will be cached against the token, so that future receipts of the same token are more
    /// efficient.  The time a token is cached for can be configured.
    ///
    /// One claim (by default, `sub`) will be considered the 'identity' of the bearer, and will be used to populate the
    /// `id` and `displayName` properties of the profile.  This claim can be customized by setting the `subject` option
    /// to the name of the appropriate claim in your `Claims`.
    ///
    /// If you require additional claims to appear as properties of the profile, supply the `userProfileDelegate` option.
    /// The `UserProfileDelegate` will be given a dictionary containing the claims of the JWT from which it can populate
    /// the profile.
    /// - Parameter verifier: Determines the key and algorithm used to verify the received JWT.
    /// - Parameter options: A dictionary of plugin specific options. The keys are defined in `CredentialsJWTOptions`.
    /// - Parameter tokenTimeToLive: How long the token should remain cached (in seconds).  The default is `nil`, which means the token will be cached indefinitely.
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
    /// Behaviour depends on the presence (and value) of the `X-token-type` header:
    ///  - `X-token-type: JWT`: Expects a valid JWT string in the `Authorization` header.
    ///  - no `X-token-type` header: Attempts to extract a valid JWT string from the `Authorization` header, but will defer to other plugins (rather than failing authentication).
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

        let noTokenType = (request.headers["X-token-type"] == nil)
        if  noTokenType || request.headers["X-token-type"] == .some(self.name) {
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
                        let optionalDict = try? JSONSerialization.jsonObject(with: claimsData, options: []),
                        let dictionary = optionalDict as? [String:Any]
                        else {
                            Log.error("Couldn't decode claims")
                            return onFailure(nil, nil)
                    }
                    // Ensure claims contain the expected subject claim (default `sub`)
                    guard let subjectClaim = dictionary[subject] else {
                        Log.warning("Unable to create user profile: JWT claims do not contain '\(subject)'")
                        return onFailure(nil, nil)
                    }
                    // Convert subject claim value to a String
                    let userid = String("\(subjectClaim)")
                    let userProfile = UserProfile(id: userid , displayName: userid, provider: "JWT")
                    
                    delegate?.update(userProfile: userProfile, from: dictionary)
                    
                    let newCacheElement = BaseCacheElement(profile: userProfile)
        
                    self.usersCache?.setObject(newCacheElement, forKey: key)
                    onSuccess(userProfile)
                } catch {
                    // Authorization header did not contain a valid JWT
                    if (noTokenType) {
                        // No X-token-type header: Allow other plugins to attempt to authenticate the Authorization header
                        onPass(nil, nil)
                    } else {
                        Log.info("JWT can't be verified: \(error)")
                        onFailure(nil, nil)
                    }
                }
                
            } else {
                // No Authorization header
                if (noTokenType) {
                    // No X-token-type header: Allow other plugins to authenticate
                    onPass(nil, nil)
                } else {
                    Log.debug("Missing authorization header")
                    onFailure(nil, nil)
                }
            }
            
        } else {
            onPass(nil, nil)
        }
    }
    
}

// This extension is copied from Swift-JWT and provides the base64url encoding that a JWT
// uses to encode the data.
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
