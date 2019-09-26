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
import Credentials
import Dispatch

@testable import CredentialsJWT

// Sets option for CredentialsJWT to allow username to be used instead of sub, used in the alternate
// credentials tests.
let jwtOptions: [String:Any] = [CredentialsJWTOptions.subject: "username"]

// Credentials are set up outside the scope of the class for use within the tests.
let jwtCredentials = CredentialsJWT<TestClaims>(verifier: .hs256(key: "<PrivateKey>".data(using: .utf8)!), tokenTimeToLive: 1)
let altCredentials = CredentialsJWT<TestAlternateClaims>(verifier: .hs256(key: "<PrivateKey>".data(using: .utf8)!), options: jwtOptions)

// Sets options for CredentialsJWT to perform UserProfile manipulation using
// a delegate, making use of custom Claims.
let delegateOptions: [String:Any] = [CredentialsJWTOptions.subject: "id", CredentialsJWTOptions.userProfileDelegate: MyDelegate()]
let delegateCredentials = CredentialsJWT<TestDelegateClaims>(verifier: .hs256(key: "<PrivateKey>".data(using: .utf8)!), options: delegateOptions)

class TestRawRouteJWT : XCTestCase {

    // Initiliasting the 3 users names and token variables.
    // The actual String is generated in the setUp function before each test.

    var testUser = User(name: "Test")
    var jwtString = ""

    var testUser2 = User(name: "Test2")
    var jwtString2 = ""

    var altUser = User(name: "Alternate")
    var jwtString3 = ""

    var delegateUser = User(name: "Mr Delegate", email: "mr_delegate@foo.xyz")
    var jwtString4 = ""

    // Key used in generation and decoding of JWT strings.
    let key = "<PrivateKey>".data(using: .utf8)

    // Sets up the raw routes for the tests.
    var router = TestRawRouteJWT.setupRawRouter()

    static var allTests : [(String, (TestRawRouteJWT) -> () throws -> Void)] {
        return [
        ("testCorrectToken", testCorrectToken),
        ("testCorrectToken2", testCorrectToken2),
        ("testInvalidToken", testInvalidToken),
        ("testWrongClaims", testWrongClaims),
        ("testSubjectName", testSubjectName),
        ("testCacheEntry", testCacheEntry),
        ("testTokenTimeToLive", testTokenTimeToLive),
        ("testSkipAuthentication", testSkipAuthentication),
        ("testMissingTokenType", testMissingTokenType),
        ("testMissingAccessToken", testMissingAccessToken),
        ("testPassOnMissingTokenType", testPassOnMissingTokenType),
      ]

    }

    // Function that creates the logger used in debugging.
    private static let initOnce: () = {
        PrintLogger.use(colored: true)
    }()

    // setUp function that creates the JWT
    override func setUp() {
        super.setUp()
        TestRawRouteJWT.initOnce

        // Clears cache before every test
        jwtCredentials.usersCache?.removeAllObjects()

        // User 1 JWT created.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generaterawjwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("Couldn't read response")
                        return expectation.fulfill()
                    }
                    self.jwtString = body
                } catch {
                    XCTFail("Couldn't read string from response")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.testUser))
                } catch {
                    XCTFail("Failed to send data")
                    expectation.fulfill()
                }
            })
        }

        // User 2 JWT created.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generaterawjwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("Couldn't read response")
                        return expectation.fulfill()
                    }
                    self.jwtString2 = body
                } catch {
                    XCTFail("Couldn't read string from response")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.testUser2))
                } catch {
                    XCTFail("Failed to send data")
                    expectation.fulfill()
                }
            })
        }

        // User 3 JWT created. User 3 uses the alternate test claims.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generaterawjwtalt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("Couldn't read response")
                        return expectation.fulfill()
                    }
                    self.jwtString3 = body
                } catch {
                    XCTFail("Couldn't read string from response")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.altUser))
                } catch {
                    XCTFail("Failed to send data")
                    expectation.fulfill()
                }
            })
        }

        // User 4 JWT created. User 4 uses the delegate test claims.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generateRawJwtDelegate", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("Couldn't read response")
                        return expectation.fulfill()
                    }
                    self.jwtString4 = body
                } catch {
                    XCTFail("Couldn't read string from response")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.delegateUser))
                } catch {
                    XCTFail("Failed to send data")
                    expectation.fulfill()
                }
            })
        }
    }

    // Tests that when a correct token is supplied a valid UserProfile is created.
    func testCorrectToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return expectation.fulfill()
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "Test", displayName: "Test", provider: "JWT")
                    XCTAssertEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString])
        }
    }

    // Tests that when a second correct token is supplied a second valid UserProfile is created.
    func testCorrectToken2() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return expectation.fulfill()
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "Test2", displayName: "Test2", provider: "JWT")
                    XCTAssertEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString2])
        }
    }

    // Tests that when a JWT is supplied that contains custom claims, to a route
    // whose CredentialsJWT is configured with a suitable delegate, the profile
    // contains the values of those custom claims (fullName and email).
    func testDelegateToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawTokenAuthDelegate", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return expectation.fulfill()
                    }
                    let profile = body
                    let expectedProfile = "Mr Delegate,mr_delegate@foo.xyz"
                    XCTAssertEqual(profile, expectedProfile)
                    //TODO
                } catch {
                    XCTFail("Could not decode response: \(error)")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString4])
        }
    }

    // Tests that when an incorrect token is supplied an invalid token is supplied, user is unauthorized.
    func testInvalidToken() {
            performServerTest(router: router) { expectation in
                self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                    expectation.fulfill()
                }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + "Wrong"])
            }
        }

    // Tests that when a correct token with the wrong set of claims is supplied, user is unauthorized.
    func testWrongClaims() {
            performServerTest(router: router) { expectation in
                self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                    expectation.fulfill()
                }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString3])
            }
        }

    // Tests that when a correct token is supplied (that does not contain a sub claim) to a
    // CredentialsJWT instance where the subject option has username instead, that the user is
    // authorized.
    func testSubjectName() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauthalt", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return expectation.fulfill()
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "Alternate", displayName: "Alternate", provider: "JWT")
                    XCTAssertEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString3])
        }
    }

    // Tests that once a profile has been cached it can be retrieved from the cache and
    // authorize a user.
    func testCacheEntry() {

        let userProfile = UserProfile(id: "Cache" , displayName: "Cache", provider: "JWT")
        #if os(Linux)
            let key = NSString(string: jwtString)
        #else
            let key = jwtString as NSString
        #endif

        let newCacheElement = BaseCacheElement(profile: userProfile)

        jwtCredentials.usersCache?.setObject(newCacheElement, forKey: key)

        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return expectation.fulfill()
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "Cache", displayName: "Cache", provider: "JWT")
                    XCTAssertEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString])
        }
        

    }

    // Tests that once a token has expired it is evicted from the cache, then from using user 1's jwt
    // that the user is authorized but with the User profile id being "Test" and not "Cache".
    func testTokenTimeToLive() {

        let userProfile = UserProfile(id: "Cache" , displayName: "Cache", provider: "JWT")
        #if os(Linux)
            let key = NSString(string: jwtString)
        #else
            let key = jwtString as NSString
        #endif

        let newCacheElement = BaseCacheElement(profile: userProfile)

        jwtCredentials.usersCache?.setObject(newCacheElement, forKey: key)

        self.performServerTest(router: self.router) { expectation in
            // Dispatch queue is used to allow 2 seconds to pass before authenticating, meaning
            // that the token has exceeded its lifespan and has been evicted from the cache.
            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                    do {
                        guard let body = try response?.readString() else {
                            XCTFail("No response body")
                            return expectation.fulfill()
                        }
                        let profile = body
                        let testProfile = UserProfile(id: "Test", displayName: "Test", provider: "JWT")
                        XCTAssertEqual(profile, testProfile.id)
                    } catch {
                        XCTFail("Could not decode response: \(error)")
                        expectation.fulfill()
                    }
                    expectation.fulfill()
                }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString])
            }
        }

    }

    // Tests that when a request to a raw route that includes this middleware does not
    // contain the matching X-token-type header, the middleware skips authentication and the
    // google handler is instead invoked.
    func testSkipAuthentication() {
        let googleToken = "Token Google"
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return expectation.fulfill()
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "TestGoogle", displayName: "TestGoogle", provider: "GoogleToken")
                    XCTAssertEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                    expectation.fulfill()
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "GoogleToken", "access_token" : googleToken])
        }

    }

    // Tests that when a request to a raw route that includes this middleware contains
    // a valid Authorization header, but does not contain an X-token-type header, the
    // middleware attempts authentication anyway and authentication succeeds.
    func testMissingTokenType() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Authorization" : "Bearer " + self.jwtString])
        }
    }

    // Tests that when a request to a raw route that includes this middleware contains
    // the matching X-token-type header, but does not supply 'Authorization', the middleware
    // fails authentication and returns unauthorized.
    func testMissingAccessToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: {response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["X-token-type" : "JWT"])
        }
    }

    // Tests that CredentialsJWT will successfully defer to other plugins after
    // speculatively attempting to authenticate a request containing an Authorization
    // header but no `X-token-type` header.
    // In this case, we have registered CredentialsHTTPBasic after CredentialsJWT.
    func testPassOnMissingTokenType() {
        guard let httpBasicCredentials = "John:12345".data(using: .utf8)?.base64EncodedString() else {
            return XCTFail("Couldn't create credentials string")
        }
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                guard let response = response else {
                    return XCTFail("ERROR!!! ClientRequest response object was nil")
                }
                XCTAssertEqual(response.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(response.statusCode)")
                do {
                    let responseString = try response.readString()
                    XCTAssertEqual(responseString, "John")
                } catch {
                    XCTFail("Unable to read response string")
                }
                expectation.fulfill()
            }, headers: ["Authorization" : "Basic " + httpBasicCredentials])
        }
    }

    // Function that creates the raw routes for the router.
    static func setupRawRouter() -> Router {
        let router = Router()
        let key = "<PrivateKey>".data(using: .utf8)
        let jwtSigner = JWTSigner.hs256(key: key!)
        let tokenCredentials = Credentials()
        let altTokenCredentials = Credentials()
        let delegateTokenCredentials = Credentials()

        // Simple verifier that expects test values
        let httpBasicVerifier: TestCredentialsHTTPBasic.VerifyPassword = { user, pass, callback in
            if user == "John" && pass == "12345" {
                callback(UserProfile(id: user, displayName: user, provider: "basic"))
            } else {
                callback(nil)
            }
        }

        tokenCredentials.register(plugin: jwtCredentials)
        tokenCredentials.register(plugin: TestCredentialsGoogleToken())
        tokenCredentials.register(plugin: TestCredentialsHTTPBasic(verifyPassword: httpBasicVerifier))
        altTokenCredentials.register(plugin: altCredentials)
        delegateTokenCredentials.register(plugin: delegateCredentials)

        router.get("/rawtokenauth", middleware: tokenCredentials)
        router.get("/rawtokenauth") { request, response, next in
            guard let userProfile = request.userProfile else {
                Log.verbose("Failed raw token authentication")
                response.status(.unauthorized)
                try response.end()
                return
            }
            response.send("\(userProfile.id)")
            next()
        }

        router.get("/rawtokenauthalt", middleware: altTokenCredentials)
        router.get("/rawtokenauthalt") { request, response, next in
            guard let userProfile = request.userProfile else {
                Log.verbose("Failed raw token authentication")
                response.status(.unauthorized)
                try response.end()
                return
            }
            response.send("\(userProfile.id)")
            next()
        }

        router.get("/rawTokenAuthDelegate", middleware: delegateTokenCredentials)
        router.get("/rawTokenAuthDelegate") { request, response, next in
            guard let userProfile = request.userProfile else {
                Log.verbose("Failed raw token authentication")
                return try response.status(.unauthorized).end()
            }
            guard let email = userProfile.emails?.first?.value else {
                Log.verbose("UserProfile e-mail was not populated")
                return try response.status(.unauthorized).end()
            }
            response.send("\(userProfile.displayName),\(email)")
            next()
        }

        // Route that generates a jwt from a given User's name.
        router.post("/generaterawjwt") { request, response, next in
            let credentials = try request.read(as: User.self)
            // Users credentials are authenticated
            let myClaims = TestClaims(sub: credentials.name)
            var myJWT = JWT(claims: myClaims)
            let signedJWT = try myJWT.sign(using: jwtSigner)
            response.send(signedJWT)
            next()
        }

        // Route that generates a jwt from a given User's name.
        router.post("/generaterawjwtalt") { request, response, next in
            let credentials = try request.read(as: User.self)
            // Users credentials are authenticated
            let myClaims = TestAlternateClaims(username: credentials.name)
            var myJWT = JWT(claims: myClaims)
            let signedJWT = try myJWT.sign(using: jwtSigner)
            response.send(signedJWT)
            next()
        }

        // Route that generates a jwt from a given User's name.
        router.post("/generateRawJwtDelegate") { request, response, next in
            let credentials = try request.read(as: User.self)
            // Users credentials are authenticated
            let myClaims = TestDelegateClaims(id: 123, fullName: credentials.name, email: credentials.email!)
            var myJWT = JWT(claims: myClaims)
            let signedJWT = try myJWT.sign(using: jwtSigner)
            response.send(signedJWT)
            next()
        }

        return router

    }

}
