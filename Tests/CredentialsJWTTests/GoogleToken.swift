/**
 * Copyright IBM Corporation 2016, 2017
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

// CLASS TAKEN FROM CREDENTIALS GOOGLE AND USED ONLY IN TESTS.
public class CredentialsGoogleToken: CredentialsPluginProtocol {

    public var usersCache: NSCache<NSString, BaseCacheElement>?

    public var name: String {
        return "GoogleToken"
    }

    public var redirecting: Bool {
        return false
    }
    public func authenticate(request: RouterRequest, response: RouterResponse,
                             options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                             onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             inProgress: @escaping () -> Void) {
        if let type = request.headers["X-token-type"], type == name {
            if request.headers["access_token"] != nil {
                let googleProfile = UserProfile(id: "TestGoogle", displayName: "TestGoogle", provider: "GoogleToken")
                onSuccess(googleProfile)
            }
            else {
                onFailure(nil, nil)
            }
        }
        else {
            onPass(nil, nil)
        }
    }
}
