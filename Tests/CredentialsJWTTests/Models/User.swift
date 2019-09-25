// A User structure that can be passed into the generate jwt route.
struct User: Codable {
    let name: String
    let email: String?
    init(name: String, email: String? = nil) {
        self.name = name
        self.email = email
    }
}

