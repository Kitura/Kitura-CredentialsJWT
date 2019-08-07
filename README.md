<p align="center">
    <a href="http://kitura.io/">
        <img src="https://raw.githubusercontent.com/IBM-Swift/Kitura/master/Sources/Kitura/resources/kitura-bird.svg?sanitize=true" height="100" alt="Kitura">
    </a>
</p>


<p align="center">
    <a href="http://www.kitura.io/">
    <img src="https://img.shields.io/badge/docs-kitura.io-1FBCE4.svg" alt="Docs">
    </a>
    <a href="https://travis-ci.org/IBM-Swift/Kitura-CredentialsJWT">
    <img src="https://travis-ci.org/IBM-Swift/Kitura-CredentialsJWT.svg?branch=master" alt="Build Status - Master">
    </a>
    <img src="https://img.shields.io/badge/os-macOS-green.svg?style=flat" alt="macOS">
    <img src="https://img.shields.io/badge/os-linux-green.svg?style=flat" alt="Linux">
    <img src="https://img.shields.io/badge/license-Apache2-blue.svg?style=flat" alt="Apache 2">
    <a href="http://swift-at-ibm-slack.mybluemix.net/">
    <img src="http://swift-at-ibm-slack.mybluemix.net/badge.svg" alt="Slack Status">
    </a>
</p>

# Kitura-CredentialsJWT

Plugin for the Credentials framework that supports authentication using JWTs.

## Summary
Plugin for [Kitura-Credentials](https://github.com/IBM-Swift/Kitura-Credentials) framework that supports authentication using [JSON Web Tokens](https://jwt.io/).

## Table of Contents
* [Swift version](#swift-version)
* [License](#license)

## Swift version
The latest version of Kitura-CredentialsJWT requires **Swift 4.0** or newer. You can download this version of the Swift binaries by following this [link](https://swift.org/download/). Compatibility with other Swift versions is not guaranteed.

## Example of JWT authentication for Codable routes

A Kitura Codable route can be authenticated using a JWT by using the `JWT<C: Claims>` type (defined by [Swift-JWT](https://github.com/IBM-Swift/Swift-JWT)) as a Type-Safe Middleware:

```swift
import SwiftJWT
import CredentialsJWT

// Define the claims that must appear in the JWT
struct MyClaims: Claims {
    // Subject's id (e.g. name)
    let sub: String
}

// Set up TypeSafeJWT by specifying the method for verifying a JWT signature
let key = "<PrivateKey>".data(using: .utf8)!
TypeSafeJWT.verifier = .hs256(key: key)

// Use the JWT type as a Type-Safe Middleware to protect a route. The hanlder will only be
// invoked if the JWT can be successfully verified, and contains the required claims.
router.get("/protected") {  (jwt: JWT<MyClaims>, respondWith: (User?, RequestError?) -> Void) in
    // (Decide whether to permit the user access to this resource, based on the JWT claims)
    // Send the requested resource:
    let user = User(name: jwt.claims.sub)
    respondWith(user, nil)
}
```

## License
This library is licensed under Apache 2.0. Full license text is available in [LICENSE](LICENSE.txt).
