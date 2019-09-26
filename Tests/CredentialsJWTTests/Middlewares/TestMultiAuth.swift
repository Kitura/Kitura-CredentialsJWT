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
import Credentials
import CredentialsJWT

// Trivial multi-auth credentials that authenticates using either JWT or Basic
// credentials.
struct TestMultiAuth: TypeSafeMultiCredentials {
    var id: String
    var provider: String
    var profile: JWT<TestClaims>?

    static var authenticationMethods: [TypeSafeCredentials.Type] = [JWT<TestClaims>.self, TestBasicAuthedUser.self]

    init(successfulAuth: TypeSafeCredentials) {
        self.id = successfulAuth.id
        self.provider = successfulAuth.provider
        switch(successfulAuth.self) {
        case let jwt as JWT<TestClaims>:
            self.profile = jwt
        default:
            self.profile = nil
        }
    }
}
