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

// Credit: https://stackoverflow.com/questions/42459484/make-a-swift-dictionary-where-the-key-is-type
struct AnyHashableMetatype: Hashable {
    static func == (lhs: AnyHashableMetatype, rhs: AnyHashableMetatype) -> Bool {
        return lhs.base == rhs.base
    }
    let base: Any.Type

    init(_ base: Any.Type) {
        self.base = base
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(ObjectIdentifier(base))
    }
}
