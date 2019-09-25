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

import SwiftJWT

// A claims structure that will be used for the tests.  The `sub` claim holds the users name.
struct TestClaims: Claims, Equatable {

    var sub: String

   // Testing requirement: Equatable
    static func == (lhs: TestClaims, rhs: TestClaims) -> Bool {
        return
            lhs.sub == rhs.sub
    }
}

// An alternate claims structure that will be used for the tests.
// The `username` holds the user's identity.
struct TestAlternateClaims: Claims, Equatable {

    var username: String

   // Testing requirement: Equatable
    static func == (lhs: TestAlternateClaims, rhs: TestAlternateClaims) -> Bool {
        return
            lhs.username == rhs.username
    }
}

// A claims structure containing custom claims that should be extracted as part of the
// UserProfile. The `id` holds the user's identity.
struct TestDelegateClaims: Claims, Equatable {
    let id: Int
    let fullName: String
    let email: String

    // Testing requirement: Equatable
     static func == (lhs: TestDelegateClaims, rhs: TestDelegateClaims) -> Bool {
         return
            lhs.id == rhs.id && lhs.fullName == rhs.fullName && lhs.email == rhs.email
     }
}
