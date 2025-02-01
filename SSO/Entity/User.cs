using Microsoft.AspNetCore.Identity;

namespace SSO.Entity
{
    public class User : IdentityUser
    {
        public string UserName { get; set; }
        public string FullName { get; set; }
        public string PhoneNumber { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }
}
