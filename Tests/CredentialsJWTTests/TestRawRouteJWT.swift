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

@testable import CredentialsJWT

class TestRawRouteJWT : XCTestCase {

    // A claims structure that will be used for the tests.  The `sub` claim holds the users name.
    struct TestClaims: Claims, Equatable {

        var sub: String

       // Testing requirement: Equatable
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

    // Initiliasting the 3 users names and token variables.
    //The actual String is generated in the setUp function before each test.

    var testUser = User(name: "Test")
    var jwtString = ""

    var testUser2 = User(name: "Test2")
    var jwtString2 = ""

    var testUser3 = User(name: "Test3")
    var jwtString3 = ""

    // Key used in generation and decoding of JWT strings.
    let key = "<PrivateKey>".data(using: .utf8)

    // Sets up the codable routes for the tests.
    var router = TestRawRouteJWT.setupRawRouter()

    static var allTests : [(String, (TestRawRouteJWT) -> () throws -> Void)] {
        return [
        ("testDefaultTokenProfile", testDefaultTokenProfile),
        ("testCorrectToken", testCorrectToken),
        ("testIncorrectToken", testIncorrectToken),
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
        TestRawRouteJWT.initOnce

        // User 1 JWT created.
        performServerTest(router: router) { expectation in
            self.performRequest(method: "post", path: "/generaterawjwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("Couldn't read response")
                        return
                    }
                    self.jwtString = body
                } catch {

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
            self.performRequest(method: "post", path: "/generaterawjwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("Couldn't read response")
                        return
                    }
                    do {
                        self.jwtString2 = body
                    }
                } catch {

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
            self.performRequest(method: "post", path: "/generaterawjwt", contentType: "application/json", callback: { response in
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("Couldn't read response")
                        return
                    }
                    do {
                        self.jwtString3 = body
                    }
                } catch {

                }
                expectation.fulfill()
            }, requestModifier: { request in
                do {
                    try request.write(from: JSONEncoder().encode(self.testUser3))
                } catch {
                    XCTFail("Couldn't send data")
                }
            })
        }

    }

    // Tests that the pre-constructed JWT type maps correctly to the JWT decoded from
    // the jwtString earlier defined.
    func testDefaultTokenProfile() {
        do {
            guard let profileInstance = try? JWT<TestClaims>(jwtString: jwtString, verifier: .hs256(key: key!)) else {
            return XCTFail("Failed to generate JWT from given JWT string")
        }
            // An equivalent test profile, constructed directly.
            let testTokenProfile = JWT(claims: TestClaims(sub: "Test"))
            XCTAssertEqual(profileInstance.claims, testTokenProfile.claims, "The reference JWT instance did not match the instance decoded from the jwt string")
        } catch {
            XCTFail("error")
        }
    }

    func testCorrectToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "Test", displayName: "Test", provider: "JWT")
                    XCTAssertEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString])
        }
    }

    func testIncorrectToken() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "Test", displayName: "Test", provider: "JWT")
                    XCTAssertNotEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + self.jwtString2])
        }
    }

    func testInvalidToken() {
            performServerTest(router: router) { expectation in
                self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                    XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                    XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                    expectation.fulfill()
                }, headers: ["X-Token-Type" : "JWT", "Authorization" : "Bearer " + "Wrong"])
            }
        }

    func testGoogleTokenType() {

        let googleToken = "Token Google"

        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.OK, "HTTP Status code was \(String(describing: response?.statusCode))")
                do {
                    guard let body = try response?.readString() else {
                        XCTFail("No response body")
                        return
                    }
                    let profile = body
                    let testProfile = UserProfile(id: "TestGoogle", displayName: "TestGoogle", provider: "GoogleToken")
                    XCTAssertEqual(profile, testProfile.id)
                } catch {
                    XCTFail("Could not decode response: \(error)")
                }
                expectation.fulfill()
            }, headers: ["X-Token-Type" : "GoogleToken", "access_token" : googleToken])
        }

    }


    // Tests that when a request to a Codable route that includes this middleware does not
    // contain the matching X-token-type header, the middleware skips authentication and a
    // second handler is instead invoked.
    func testMissingTokenType() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/rawtokenauth", callback: { response in
                XCTAssertNotNil(response, "ERROR!!! ClientRequest response object was nil")
                XCTAssertEqual(response?.statusCode, HTTPStatusCode.unauthorized, "HTTP Status code was \(String(describing: response?.statusCode))")
                expectation.fulfill()
            }, headers: ["Authorization" : "Bearer " + self.jwtString])
        }
    }

    // Tests that when a request to a Codable route that includes this middleware contains
    // the matching X-token-type header, but does not supply an access_token, the middleware
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

    // Function that creates the codable routes for the router.
    static func setupRawRouter() -> Router {
        let router = Router()
        let key = "<PrivateKey>".data(using: .utf8)
        let jwtSigner = JWTSigner.hs256(key: key!)
        let tokenCredentials = Credentials()

        tokenCredentials.register(plugin: CredentialsJWT<TestClaims>(verifier: .hs256(key: key!)))
        tokenCredentials.register(plugin: CredentialsGoogleToken())

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

        return router

    }

}
