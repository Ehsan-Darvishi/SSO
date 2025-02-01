using System.ComponentModel.DataAnnotations;

namespace SSO.ServiceModel
{
    public class OtpVerifyRequest
    {
        [Required]
        public string PhoneNumber { get; set; }

        [Required]
        public string Otp { get; set; }
    }
}
