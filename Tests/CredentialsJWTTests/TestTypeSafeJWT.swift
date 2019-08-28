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

    // A claims structure that will be used for the tests.  The `sub` claim holds the users name.
    struct TestClaims: Claims, Equatable {

        var sub: String
        
        static func == (lhs: TestClaims, rhs: TestClaims) -> Bool {
            return
                lhs.sub == rhs.sub
        }
    }

    // A User structure that can be passed into the generate jwt route.
    struct User: Codable {
        var name: String
    }

    // An AccessToken structure that holds the access token String for the JWT.
    struct AccessToken: Codable {
        let accessToken: String
    }

    // Initiliasting the 3 users names and token variables.  The actual String is generated in the setUp function before each test.

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
        ("testDefaultTokenProfile", testDefaultTokenProfile),
        ("testCache", testCache),
        ("testTwoInCache", testTwoInCache),
        ("testCacheEviction", testCacheEviction),
        ("testCachedProfile", testCachedProfile),
        ("testMissingTokenType", testMissingTokenType),
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
        TypeSafeJWT.cacheSize = 2
        JWT<TestClaims>.deleteCache()
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generatejwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString(), let responseData = body.data(using: .utf8) else {
                        XCTFail("Couldn't read response")
                        return
                    }
                    do {
                        self.jwtToken = try JSONDecoder().decode(AccessToken.self, from: responseData)
                        self.jwtString = self.jwtToken.accessToken
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
                    try request.write(from: JSONEncoder().encode(self.testUser))
                } catch {
                    XCTFail("Couldn't write")
                }
            })
        }

        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generatejwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString(), let responseData = body.data(using: .utf8) else {
                        XCTFail("Couldn't read response")
                        return
                    }
                    do {
                        self.jwtToken2 = try JSONDecoder().decode(AccessToken.self, from: responseData)
                        self.jwtString2 = self.jwtToken2.accessToken
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
                    try request.write(from: JSONEncoder().encode(self.testUser2))
                } catch {
                    XCTFail("Couldn't write")
                }
            })
        }

        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generatejwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString(), let responseData = body.data(using: .utf8) else {
                        XCTFail("Couldn't read response")
                        return
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
                    XCTFail("Couldn't write")
                }
            })
        }

    }
    
    
    func testDefaultTokenProfile() {
        do {
            guard let jwtInstance = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
            return XCTFail("Google JSON response cannot be decoded to GoogleTokenProfile")
        }
        let profileInstance = jwtInstance.claims
        // An equivalent test profile, constructed directly.
        let testTokenProfile = TestClaims(sub: "Test")
        XCTAssertEqual(profileInstance, testTokenProfile, "The reference GoogleTokenProfile instance did not match the instance decoded from the Google JSON response")
        } catch {
            XCTFail("error")
        }
    }
    
    // Tests that a profile can be saved and retreived from the cache
    func testCache() {
        guard let jwtInstance = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
            return XCTFail("Google JSON response cannot be decoded to TestGoogleToken")
        }
        let profileInstance = jwtInstance.claims
        JWT<TestClaims>.saveInCache(profile: jwtInstance, token: jwtString)
        guard let cacheJWT = JWT<TestClaims>.getFromCache(token: jwtString) else {
            return XCTFail("Failed to get from cache")
        }
        let cacheProfile = cacheJWT.claims
        XCTAssertEqual(cacheProfile, profileInstance, "retrieved different profile from cache")
    }

    
    
    // Tests that two different profiles can be saved and retreived from the cache
    func testTwoInCache() {
        guard let profileInstance1 = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
            return XCTFail("Google JSON response cannot be decoded to TestGoogleToken")
        }
        guard let profileInstance2 = try? JWT<TestClaims>(jwtString: jwtString2, verifier: .hs256(key: key!)) else {
            return XCTFail("Google JSON response cannot be decoded to GoogleTokenProfile")
        }
        JWT.saveInCache(profile: profileInstance1, token: jwtString)
        JWT.saveInCache(profile: profileInstance2, token: jwtString2)
        guard let cacheProfile1 = JWT<TestClaims>.getFromCache(token: jwtString) else {
            return XCTFail("Failed to get from cache")
        }
        guard let cacheProfile2 = JWT<TestClaims>.getFromCache(token: jwtString2) else {
            return XCTFail("Failed to get from cache")
        }
        XCTAssertEqual(cacheProfile1.claims, profileInstance1.claims, "retrieved different profile from cache1")
        XCTAssertEqual(cacheProfile2.claims, profileInstance2.claims, "retrieved different profile from cache2")
    }

    // Tests that a user can set a limit on the size of the token cache. We test that the
    // least-used cache entry is purged from a cache with capacity 2 when a third entry is
    // inserted.
    // Note that this test uses a separate type (TestGoogleTokenCache instead of
    // TestGoogleToken) from all other tests, because there is no API for resetting the
    // token cache on a type, and we do not want this test's behaviour to be influenced by
    // the execution of previous tests.
    

    func testCacheEviction() {

        guard let profileInstance1 = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
        return XCTFail("Google JSON response cannot be decoded to TestGoogleToken")
        }
        guard let profileInstance2 = try? JWT<TestClaims>(jwtString: jwtString2, verifier: .hs256(key: key!)) else {
        return XCTFail("Google JSON response cannot be decoded to GoogleTokenProfile")
        }
        guard let profileInstance3 = try? JWT<TestClaims>(jwtString: jwtString3, verifier: .hs256(key: key!)) else {
        return XCTFail("Google JSON response cannot be decoded to GoogleTokenProfile")
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
                            return
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

    func testMissingTokenType() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/multipleHandlers", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString(), let profileJSON = body.data(using: .utf8) else {
                        XCTFail("No response body")
                        return
                    }
                    let testResponse = try JSONDecoder().decode(JWT<TestClaims>.self, from: profileJSON)
                    let expectedResponse = JWT(claims: TestClaims(sub: "Test"))
                    XCTAssertEqual(testResponse.claims, expectedResponse.claims, "Response from second handler did not contain expected data")
                } catch {
                    XCTFail("Could not decode response: \(error)")
                }
                expectation.fulfill()
            }, headers: ["Authorization" : "Bearer " + self.jwtString])
        }
    }

    func testMissingAccessToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/multipleHandlers", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["X-token-type" : "JWT"])
        }
    }

        
    static func setupCodableRouter() -> Router {
        

        let router = Router()
        
        // Inside app.postInit()
        router.post("/generatejwt") { (user: User, respondWith: (AccessToken?, RequestError?) -> Void) in
            var jwt = JWT(claims: TestClaims(sub: user.name))
            guard let key = "<PrivateKey>".data(using: .utf8),
                let signedJWT = try? jwt.sign(using: .hs256(key: key))
            else {
                return respondWith(nil, .internalServerError)
            }
            respondWith(AccessToken(accessToken: signedJWT), nil)
        }
        
        router.get("/singleHandler") { (profile: JWT<TestClaims>, respondWith: (JWT<TestClaims>?, RequestError?) -> Void) in
            respondWith(profile, nil)
        }

        router.get("/multipleHandlers") { (profile: JWT<TestClaims>, respondWith: (JWT<TestClaims>?, RequestError?) -> Void) in
            respondWith(profile, nil)
        }

        router.get("/multipleHandlers") { (respondWith: (JWT<TestClaims>?, RequestError?) -> Void) in
            respondWith(JWT(claims: TestClaims(sub: "Test")), nil)
        }
        
        return router
        
    }
    
}
