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

import Foundation
import XCTest
import SwiftJWT
import Kitura
import KituraNet
import LoggerAPI

@testable import CredentialsJWT

class TestTypeSafeJWT : XCTestCase {

    // A User structure that can be passed into the generate jwt route.
    struct User: Codable {
        var name: String
    }

    // An AccessToken structure that holds the access token String for the JWT.
    struct AccessToken: Codable {
        let accessToken: String
    }

    // Initiliasting the 3 users names and token variables.
    //The actual String is generated in the setUp function before each test.

    var testUser = User(name: "Test")
    var jwtToken = AccessToken(accessToken: "")
    var jwtString = ""

    var testUser2 = User(name: "Test2")
    var jwtToken2 = AccessToken(accessToken: "")
    var jwtString2 = ""

    var testUser3 = User(name: "Test3")
    var jwtToken3 = AccessToken(accessToken: "")
    var jwtString3 = ""
    
    // Key used in generation and decoding of JWT strings.
    let key = "<PrivateKey>".data(using: .utf8)

    // Sets up the codable routes for the tests.
    var router = TestTypeSafeJWT.setupCodableRouter()
    
    static var allTests : [(String, (TestTypeSafeJWT) -> () throws -> Void)] {
        return [
        ("testCache", testCache),
        ("testTwoInCache", testTwoInCache),
        ("testCacheEviction", testCacheEviction),
        ("testCachedProfile", testCachedProfile),
        ("testGoodToken", testGoodToken),
        ("testBadToken", testBadToken),
        ("testMissingTokenTypeJWT", testMissingTokenTypeJWT),
        ("testMissingTokenTypeBasic", testMissingTokenTypeBasic),
        ("testMissingAccessToken", testMissingAccessToken)
      ]
        
    }

    // Function that creates the logger used in debugging.
    private static let initOnce: () = {
        PrintLogger.use(colored: true)
    }()

    // setUp function that creates the JWT
    override func setUp() {
        super.setUp()
        TestTypeSafeJWT.initOnce

        //Sets cache size to two for testTwoInCache test.
        TypeSafeJWT.cacheSize = 2

        // Clears cache before every test
        JWT<TestClaims>.deleteCache()

        // User 1 JWT created.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generatejwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString(), let responseData = body.data(using: .utf8) else {
                        XCTFail("Couldn't read response")
                        return expectation.fulfill()
                    }
                    self.jwtToken = try JSONDecoder().decode(AccessToken.self, from: responseData)
                    self.jwtString = self.jwtToken.accessToken
                } catch {
                    XCTFail("Failed to decode JSON")
                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.testUser))
                } catch {
                    XCTFail("Failed to send data")
                }
            })
        }

        // User 2 JWT created.  Users 2 and 3 created for later tests where multiple tokens are needed.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generatejwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString(), let responseData = body.data(using: .utf8) else {
                        XCTFail("Couldn't read response")
                        return expectation.fulfill()
                    }
                    do {
                        self.jwtToken2 = try JSONDecoder().decode(AccessToken.self, from: responseData)
                        self.jwtString2 = self.jwtToken2.accessToken
                    }
                    catch {
                        XCTFail("\(body)")
                    }
                } catch {
                    XCTFail("Failed to decode JSON")
                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.testUser2))
                } catch {
                    XCTFail("Failed to send data")
                }
            })
        }

        // User 3 JWT created. Users 2 and 3 created for later tests where multiple tokens are needed.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generatejwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString(), let responseData = body.data(using: .utf8) else {
                        XCTFail("Couldn't read response")
                        return expectation.fulfill()
                    }
                    do {
                        self.jwtToken3 = try JSONDecoder().decode(AccessToken.self, from: responseData)
                        self.jwtString3 = self.jwtToken3.accessToken
                    }
                    catch {
                        XCTFail("\(body)")
                    }
                } catch {
                    XCTFail("Couldn't do JWT")
                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.testUser3))
                } catch {
                    XCTFail("Couldn't send data.")
                }
            })
        }

    }
    
    // Tests that a profile can be saved and retreived from the cache.
    func testCache() {
        guard let jwtInstance = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
            return XCTFail("Failed to generate JWT from given jwt string")
        }
        let profileInstance = jwtInstance.claims
        JWT<TestClaims>.saveInCache(profile: jwtInstance, token: jwtString)
        guard let cacheJWT = JWT<TestClaims>.getFromCache(token: jwtString) else {
            return XCTFail("Failed to get from cache")
        }
        let cacheProfile = cacheJWT.claims
        XCTAssertEqual(cacheProfile, profileInstance, "Retrieved different profile from cache")
    }

    // Tests that two different profiles can be saved and retreived from the cache.
    func testTwoInCache() {
        guard let profileInstance1 = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
            return XCTFail("Failed to generate JWT from given jwt string")
        }
        guard let profileInstance2 = try? JWT<TestClaims>(jwtString: jwtString2, verifier: .hs256(key: key!)) else {
            return XCTFail("Failed to generate JWT from given jwt string")
        }
        JWT.saveInCache(profile: profileInstance1, token: jwtString)
        JWT.saveInCache(profile: profileInstance2, token: jwtString2)
        guard let cacheProfile1 = JWT<TestClaims>.getFromCache(token: jwtString) else {
            return XCTFail("Failed to get from cache")
        }
        guard let cacheProfile2 = JWT<TestClaims>.getFromCache(token: jwtString2) else {
            return XCTFail("Failed to get from cache")
        }
        XCTAssertEqual(cacheProfile1.claims, profileInstance1.claims, "Retrieved different profile from cache1")
        XCTAssertEqual(cacheProfile2.claims, profileInstance2.claims, "Retrieved different profile from cache2")
    }

    // Tests that a user can set a limit on the size of the token cache. We test that the
    // least-used cache entry is purged from a cache with capacity 2 when a third entry is
    // inserted.
    func testCacheEviction() {

        guard let profileInstance1 = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
        return XCTFail("Failed to generate JWT from given jwt string")
        }
        guard let profileInstance2 = try? JWT<TestClaims>(jwtString: jwtString2, verifier: .hs256(key: key!)) else {
        return XCTFail("Failed to generate JWT from given jwt string")
        }
        guard let profileInstance3 = try? JWT<TestClaims>(jwtString: jwtString3, verifier: .hs256(key: key!)) else {
        return XCTFail("Failed to generate JWT from given jwt string")
        }
        // Insert two tokens into the cache
        JWT.saveInCache(profile: profileInstance1, token: jwtString)
        JWT.saveInCache(profile: profileInstance2, token: jwtString2)
        JWT.saveInCache(profile: profileInstance3, token: jwtString3)
        // We expect one of the entries to have been evicted, but it is not predictable
        // which one (behaviour seems to differ between macOS and Linux)
        var profileCount = 0
        if let cacheProfile1 = JWT<TestClaims>.getFromCache(token: jwtString) {
            XCTAssertEqual(cacheProfile1.claims, profileInstance1.claims, "Retrieved different cached profile for token 1")
            profileCount += 1
        }
        if let cacheProfile2 = JWT<TestClaims>.getFromCache(token: jwtString2) {
            XCTAssertEqual(cacheProfile2.claims, profileInstance2.claims, "Retrieved different cached profile for token 2")
            profileCount += 1
        }
        if let cacheProfile3 = JWT<TestClaims>.getFromCache(token: jwtString3) {
            XCTAssertEqual(cacheProfile3.claims, profileInstance3.claims, "Retrieved different cached profile for token 3")
            profileCount += 1
        }
        XCTAssertEqual(profileCount, 2, "Expected to retrieve 2 profiles from the cache, but retrieved \(profileCount)")
        }
    
    // Tests that a profile stored in the token cache can be retrieved and returned by a Codable
    // route that includes this middleware.
    func testCachedProfile() {
        
        var jwt: JWT<TestClaims>
        do {
            jwt = try JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!))
            JWT<TestClaims>.saveInCache(profile: jwt, token: jwtString)
            performServerTest(router: router) { expectation in
                self.performRequest(method: "get", path: "/singleHandler", callback: { response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                    do {
                        guard let body = try response?.readString(), let profileJSON = body.data(using: .utf8) else {
                            XCTFail("No response body")
                            return expectation.fulfill()
                        }
                        let profile = try JSONDecoder().decode(JWT<TestClaims>.self, from: profileJSON)
                        XCTAssertEqual(profile.claims, jwt.claims, "Body \(profile) is not equal to \(jwt)")
                    } catch {
                        XCTFail("Could not decode response: \(error)")
                    }
                    expectation.fulfill()
                }, headers: ["X-token-type" : "JWT", "Authorization" : "Bearer " + self.jwtString])
            }
        } catch {
           XCTFail("Failed to decode JWT: \(error)")
        }
    }

    // Tests that when a request to a Codable route that includes this middleware receives
    // an X-token-type header of 'JWT' and a valid JWT string in the Authorization header,
    // authentication succeeds.
    func testGoodToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/singleHandler", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, .OK)
                expectation.fulfill()
            }, headers: ["Authorization" : "Bearer " + self.jwtString, "X-token-type" : "JWT"])
        }
    }

    // Tests that when a request to a Codable route that includes this middleware receives
    // an X-token-type header of 'JWT' and an invalid JWT string in the Authorization
    // header, authentication fails.
    func testBadToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/singleHandler", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, .unauthorized)
                expectation.fulfill()
            }, headers: ["Authorization" : "Bearer of bad news", "X-token-type" : "JWT"])
        }
    }

    // Tests that when a request is made to a Codable route that includes this middleware
    // as one of multiple authentication methods, and the request does not contain the
    // X-token-type header, the middleware successfully authenticates a JWT token.
    func testMissingTokenTypeJWT() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/multipleAuth", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString(), let profileJSON = body.data(using: .utf8) else {
                        XCTFail("No response body")
                        return expectation.fulfill()
                    }
                    let testResponse = try JSONDecoder().decode(JWT<TestClaims>.self, from: profileJSON)
                    let expectedResponse = JWT(claims: TestClaims(sub: self.testUser.name))
                    XCTAssertEqual(testResponse.claims, expectedResponse.claims, "Response from second handler did not contain expected data")
                } catch {
                    XCTFail("Could not decode response: \(error)")
                }
                expectation.fulfill()
            }, headers: ["Authorization" : "Bearer " + self.jwtString])
        }
    }

    // Tests that when a request is made to a Codable route that includes this middleware
    // as one of multiple authentication methods, and the request does not contain the
    // X-token-type header, the JWT middleware skips and allows Basic auth to proceed.
    func testMissingTokenTypeBasic() {
        guard let httpBasicCredentials = "John:12345".data(using: .utf8)?.base64EncodedString() else {
            return XCTFail("Couldn't create credentials string")
        }
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/multipleAuth", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                // For the purposes of detecting which method of authentication was used, we
                // expect .accepted from the multipleAuth route with successful basic auth.
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.accepted)
                expectation.fulfill()
            }, headers: ["Authorization" : "Basic " + httpBasicCredentials])
        }
    }

    // Tests that when a request to a Codable route that includes this middleware contains
    // the matching X-token-type header, but does not supply 'Authorization', the middleware
    // fails authentication and returns unauthorized.
    func testMissingAccessToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/singleHandler", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["X-token-type" : "JWT"])
        }
    }

    // Function that creates the codable routes for the router.
    static func setupCodableRouter() -> Router {
        let router = Router()
        let key = "<PrivateKey>".data(using: .utf8)!
        TypeSafeJWT.verifier = .hs256(key: key)

        // Route that generates a jwt from a given User's name.
        router.post("/generatejwt") { (user: User, respondWith: (AccessToken?, RequestError?) -> Void) in
            var jwt = JWT(claims: TestClaims(sub: user.name))
            guard let signedJWT = try? jwt.sign(using: .hs256(key: key))
            else {
                return respondWith(nil, .internalServerError)
            }
            respondWith(AccessToken(accessToken: signedJWT), nil)
        }
        
        router.get("/singleHandler") { (profile: JWT<TestClaims>, respondWith: (JWT<TestClaims>?, RequestError?) -> Void) in
            respondWith(profile, nil)
        }

        router.get("/multipleAuth") { (auth: TestMultiAuth, respondWith: (JWT<TestClaims>?, RequestError?) -> Void) in
            guard let profile = auth.profile else {
                // Indicate that request was successful, using .accepted to indicate
                // that basic authentication was used instead of JWT.
                return respondWith(nil, .accepted)
            }
            respondWith(profile, nil)
        }

        return router
        
    }
    
}
