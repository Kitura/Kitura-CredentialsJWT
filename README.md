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

A package enabling Kitura to authenticate users using [JSON Web Tokens](https://jwt.io/).

## Summary

This package provides two facilities:
- `CredentialsJWT`: A plugin for the [Kitura-Credentials](https://github.com/IBM-Swift/Kitura-Credentials) framework that supports JWT (token-based) authentication,
- A `TypeSafeMiddleware` extension for the `JWT` type, enabling it to be used as authentication for Codable routes.

## Swift version
The latest version of Kitura-CredentialsJWT requires **Swift 4.0** or newer. You can download this version of the Swift binaries by following this [link](https://swift.org/download/). Compatibility with other Swift versions is not guaranteed.

## Usage

#### Add dependencies

Add the `Kitura-CredentialsJWT` dependency within your application’s `Package.swift` file. Substitute `"x.x.x"` with the latest `Kitura-CredentialsJWT` [release](https://github.com/IBM-Swift/Kitura-CredentialsJWT/releases).

```swift
.package(url: "https://github.com/IBM-Swift/Kitura-CredentialsJWT.git", from: "x.x.x")
```

Add `CredentialsJWT` to your target's dependencies:

```swift
.target(name: "example", dependencies: ["CredentialsJWT"]),
```
#### Import packages

```swift
import CredentialsJWT
```

### Using the `CredentialsJWT` plugin

This plugin requires that the following HTTP headers are present on a request:
- `X-token-type`: must be `JWT`
- `Authorization`: the JWT string, optionally prefixed with `Bearer`.

The [Swift-JWT](https://github.com/IBM-Swift/Swift-JWT) library is used to decode the token supplied in the Authorization header. To successfully decode it, you must specify the `Claims` that will be present in the JWT.

One claim (by default, `sub`) will be used to represent the identity of the bearer.  You can choose a different claim by supplying the `subject` option when creating an instance of CredentialsJWT, and you can further customize the resulting `UserProfile` by defining a `UserProfileDelegate`.

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

Following successful authentication, the `UserProfile` will be minimally populated with the two required fields - `id` and `displayName` - both with the value of the JWT's `sub` claim.  The `provider` will be set to `JWT`.

### Usage Example - custom claims

To customize the name of the identity claim, and further populate the UserProfile fields, specify the `subject` and `userProfileDelegate` options as follows:
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

// Use the JWT type as a Type-Safe Middleware to protect a route. The handler will only be
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
