import Credentials

// A UserProfileDelegate for the route accessed in testDelegateToken. Custom claims
// 'fullName' and 'email' are applied to the UserProfile 'displayName' and 'emails'
// fields.
struct MyDelegate: UserProfileDelegate {
    func update(userProfile: UserProfile, from dictionary: [String:Any]) {
        // `userProfile.id` already contains `id`
        userProfile.displayName = dictionary["fullName"]! as! String
        let email = UserProfile.UserProfileEmail(value: dictionary["email"]! as! String, type: "home")
        userProfile.emails = [email]
    }
}

