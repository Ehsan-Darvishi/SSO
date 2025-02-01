using System.ComponentModel.DataAnnotations;

namespace SSO.ServiceModel
{
    public class Login_Otp
    {
        [Required]
        public string PhoneNumber { get; set; }
    }
}
