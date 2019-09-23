/**
 * Copyright IBM Corporation 2016-2019
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

import Foundation

// Simplified copy of CredentialsHTTP, only used in tests.
class TestCredentialsHTTPBasic : CredentialsPluginProtocol {

    var name: String { return "HTTPBasic" }

    var redirecting: Bool { return false }

    var usersCache: NSCache<NSString, BaseCacheElement>?

    typealias VerifyPassword = (String, String, @escaping (UserProfile?) -> Void) -> Void
    private var verifyPassword: VerifyPassword

    init (verifyPassword: @escaping VerifyPassword, realm: String?=nil) {
        self.verifyPassword = verifyPassword
    }

    func authenticate (request: RouterRequest, response: RouterResponse,
                       options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                       onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                       onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                       inProgress: @escaping () -> Void)  {

        var authorization : String
        if let user = request.urlURL.user, let password = request.urlURL.password {
            authorization = user + ":" + password
        }
        else {
            let options = Data.Base64DecodingOptions(rawValue: 0)

            guard let authorizationHeader = request.headers["Authorization"]  else {
                onPass(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"Users\""])
                return
            }

            let authorizationHeaderComponents = authorizationHeader.components(separatedBy: " ")
            guard authorizationHeaderComponents.count == 2,
                authorizationHeaderComponents[0] == "Basic",
                let decodedData = Data(base64Encoded: authorizationHeaderComponents[1], options: options),
                let userAuthorization = String(data: decodedData, encoding: .utf8) else {
                    onPass(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"Users\""])
                    return
            }

            authorization = userAuthorization as String
        }

        let credentials = authorization.split(separator: ":", maxSplits: 1)
        guard credentials.count == 2 else {
            onFailure(.badRequest, nil)
            return
        }

        let userid = String(credentials[0])
        let password = String(credentials[1])

        verifyPassword(userid, password) { userProfile in
            if let userProfile = userProfile {
                onSuccess(userProfile)
            }
            else {
                onFailure(.unauthorized, ["WWW-Authenticate" : "Basic realm=\"Users\""])
            }
        }
    }
}
