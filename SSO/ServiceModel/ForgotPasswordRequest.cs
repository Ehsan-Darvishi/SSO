using System.ComponentModel.DataAnnotations;

namespace SSO.ServiceModel
{
    public class ForgotPasswordRequest
    {
        [Required, EmailAddress]
        public string Email { get; set; }
    }
}
