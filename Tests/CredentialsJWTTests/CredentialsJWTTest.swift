/**
 * Copyright IBM Corporation 2018
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

import XCTest

import Kitura
import KituraNet

import Foundation
import Dispatch


protocol CredentialsJWTTest {
    func expectation(_ index: Int) -> XCTestExpectation
    func waitExpectation(timeout t: TimeInterval, handler: XCWaitCompletionHandler?)
}

extension CredentialsJWTTest {

    func performServerTest(router: ServerDelegate, asyncTasks: (XCTestExpectation) -> Void...) {
        do {
            let server = try HTTPServer.listen(on: 8090, delegate: router)
            let requestQueue = DispatchQueue(label: "Request queue")

            for (index, asyncTask) in asyncTasks.enumerated() {
                let expectation = self.expectation(index)
                requestQueue.sync {
                    asyncTask(expectation)
                }
            }

            waitExpectation(timeout: 10) { error in
                // blocks test until request completes
                server.stop()
                XCTAssertNil(error);
            }
        } catch {
            XCTFail("Error: \(error)")
        }
    }

    func performRequest(method: String, host: String = "localhost", path: String, contentType: String = "text/plain", callback: @escaping ClientRequest.Callback, headers: [String: String]? = nil, requestModifier: ((ClientRequest) -> Void)? = nil) {
        var allHeaders = [String: String]()
        if  let headers = headers  {
            for  (headerName, headerValue) in headers  {
                allHeaders[headerName] = headerValue
            }
        }
        allHeaders["Content-Type"] = contentType
        let options: [ClientRequest.Options] =
                [.method(method), .hostname(host), .port(8090), .path(path), .headers(allHeaders)]
        let req = HTTP.request(options, callback: callback)
        if let requestModifier = requestModifier {
            requestModifier(req)
        }
        req.end()
    }
}

extension XCTestCase: CredentialsJWTTest {
    func expectation(_ index: Int) -> XCTestExpectation {
        let expectationDescription = "\(type(of: self))-\(index)"
        return self.expectation(description: expectationDescription)
    }

    func waitExpectation(timeout t: TimeInterval, handler: XCWaitCompletionHandler?) {
        self.waitForExpectations(timeout: t, handler: handler)
    }
}
