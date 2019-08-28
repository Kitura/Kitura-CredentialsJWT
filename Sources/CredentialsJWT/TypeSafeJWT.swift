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
import LoggerAPI
import Credentials
import Foundation
import SwiftJWT

/// The cache element to hold the JWT.
private class JWTCacheElement<C: Claims> {
    /// The user profile information stored as `TypeSafeJWT`.
    var userProfile: JWT<C>

    /// The time the UserProfile was originally created
    var createdAt: Date

    /// Initialize a `JWTCacheElement`.
    ///
    /// - Parameter profile: the `JWT` to store.
    init (profile: JWT<C>) {
        userProfile = profile
        createdAt = Date()
    }
}

// As it is not yet possible to have a stored static property on an generic type,
// this dictionary provides the storage for each specialization of JWTCacheElement<C>.
// The computed property TypeSafeJWTCache<C>.cacheForType uses an AnyHashableMetatype
// to determine which cache belongs to which specialized type.
fileprivate var _cachesForType = [AnyHashableMetatype: Any]()

// Provides access to the cache for a particular specialization of JWT<C>.
private struct TypeSafeJWTCache<C: Claims> {
    internal static var cacheForType: [String: NSCache<NSString, JWTCacheElement<C>>] {
        get {
            guard let uncastCache = _cachesForType[AnyHashableMetatype(C.self)] else {
                // There is no cache yet, create a new empty one
                return [:]
            }
            guard let cache = uncastCache as? [String: NSCache<NSString, JWTCacheElement<C>>] else {
                // This should never happen
                fatalError("The cache for type \(C.self) could not be cast to the expected type")
            }
            return cache
        }
        set {
            _cachesForType[AnyHashableMetatype(C.self)] = newValue
        }
    }
}

/// Represents the configuration for TypeSafeJWT authenication: the verification method, and the cache parameters.
/// To avoid the need to verify a token every time it is received, the token cache stores a token with a time-to-live
/// attribute, and skips verification of cached tokens while the TTL is still valid.
public struct TypeSafeJWT {
    /// The verifier to use when verifying tokens. This must be configured before tokens can be successfully authenticated,
    /// and should correspond to the JWTSigner used to issue those tokens.
    public static var verifier: JWTVerifier?
    /// The maximum size of the token cache. Defaults to `0`, which is unlimited.
    public static var cacheSize: Int = 0
    /// The length of time this token should be deemed valid before it must be verified again. Defaults to `nil`, which is unlimited.
    public static var tokenTimeToLive: TimeInterval? = nil
}

extension JWT: TypeSafeCredentials {
    
    /// Note: This field does not apply to Type-safe JWT credentials. Use the JWT claims instead.
    public var id: String {
        return "id"
    }

    /// Answers `JWT`.
    public var provider: String {
        return "JWT"
    }
    
    private static var usersCache: NSCache<NSString, JWTCacheElement<T>> {
        let key = String(reflecting: JWT.self)
        if let usersCache = TypeSafeJWTCache<T>.cacheForType[key] {
            return usersCache
        } else {
            let usersCache = NSCache<NSString, JWTCacheElement<T>>()
            Log.debug("Token cache size for \(key): \(TypeSafeJWT.cacheSize == 0 ? "unlimited" : String(describing: TypeSafeJWT.cacheSize))")
            usersCache.countLimit = TypeSafeJWT.cacheSize
            TypeSafeJWTCache.cacheForType[key] = usersCache
            return usersCache
        }
    }
    
    public static func authenticate(request: RouterRequest, response: RouterResponse,
                                    onSuccess: @escaping (JWT<T>) -> Void,
                                    onFailure: @escaping (HTTPStatusCode?, [String : String]?) -> Void,
                                    onSkip: @escaping (HTTPStatusCode?, [String : String]?) -> Void) {
        // Check whether this request declares that a Google token is being supplied
        guard let type = request.headers["X-token-type"], type == "JWT" else {
            return onSkip(nil, nil)
        }
        // Check whether a token has been supplied
        guard let authHeader = request.headers["Authorization"] else {
            return onFailure(nil, nil)
        }
        // Unpack the token from the header
        let authParts = authHeader.split(separator: " ", maxSplits: 2)
        guard authParts.count == 2, authParts[0] == "Bearer" else {
            return onFailure(nil, nil)
        }
        let token = String(authParts[1])

        //Return a cached profile from the cache associated with our type, if one is found
        //(ie. if we have successfully authenticated this token before)
        if let cacheProfile = getFromCache(token: token) {
            return onSuccess(cacheProfile)
        }
        guard let verifier = TypeSafeJWT.verifier,
            let jwt = try? JWT<T>(jwtString: token, verifier: verifier)
            else {
                return onFailure(nil, nil)
        }
        saveInCache(profile: jwt, token: token)
        onSuccess(jwt)
}
    
    static func getFromCache(token: String) -> JWT? {
        #if os(Linux)
        let key = NSString(string: token)
        #else
        let key = token as NSString
        #endif
        guard let cacheElement = JWT.usersCache.object(forKey: key) else {
            Log.debug("Cached token not found: \(token)")
            return nil
        }
        Log.debug("Cached token found: \(token)")
        if let ttl = TypeSafeJWT.tokenTimeToLive,
            cacheElement.createdAt.addingTimeInterval(ttl) < Date()
        {
            Log.debug("Cached token has expired: \(token)")
            return nil
        }
        Log.debug("Cached token is valid: \(token)")
        return cacheElement.userProfile
    }

    static func saveInCache(profile: JWT, token: String) {
        #if os(Linux)
        let key = NSString(string: token)
        #else
        let key = token as NSString
        #endif
        JWT.usersCache.setObject(JWTCacheElement(profile: profile), forKey: key)
        Log.debug("Token added to cache: \(token)")
    }

    // Used by tests to clear cache.
    static func deleteCache() {
        JWT.usersCache.removeAllObjects()
    }
}
