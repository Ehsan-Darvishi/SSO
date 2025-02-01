using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SSO.Entity;
using SSO.ServiceModel;
using SSO.Services;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace SSO.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : Controller
    {
        #region Properties
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _configuration;
        private readonly IUserStore<User> _userStore;
        private readonly OtpService _otpService;
        #endregion

        #region Constructor
        public AuthController(UserManager<User> userManager, IUserStore<User> userStore, OtpService otpService)
        {
            _userManager = userManager;
            _userStore = userStore;
            _otpService = otpService;
        }
        #endregion

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest model)
        {
            if (ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new User
            {
                UserName = model.UserName,
                Email = model.Email,
                PhoneNumber = model.PhoneNumber,
                FullName = model.FullName,
            };

            var result = await _userManager.CreateAsync(user , model.Password);
            if (!result.Succeeded) 
            {
                return BadRequest(result.Errors);
            }

            return Ok("User registered successfully");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if (user == null || !await _userManager.CheckPasswordAsync(user,model.Password)) 
            {
                return Unauthorized("Invalid credentials");
            }

            var token = GenerateJwtToken(user);
            return Ok(new { token });   
        }

        [HttpPost("forgot-password")]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordRequest model)
        {
            var user = await _userManager.FindByEmailAsync(model.Email);

            if(user == null)
            {
                return BadRequest("User not found");
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var resetLink = $"https://domain.com/reset-password?token={token}&email={user.Email}";

            // TODO: ارسال ایمیل حاوی لینک بازنشانی رمز عبور
            return Ok("Password reset link sent to your email.");
        }

        [HttpPost("send_otp")]
        public async Task<IActionResult> SendOtp([FromBody] string phoneNumber)
        {
            string otp = await _otpService.GenerateOtpAsync(phoneNumber);
            //OTP را با سرویس پیامک ارسال کنید
            return Ok(new { message = "OTP sent successfully" });
        }

        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] OtpVerifyRequest model)
        {
            bool isValid = await _otpService.VerifyOtpAsync(model.PhoneNumber, model.Otp);

            if (!isValid)
            {
                return BadRequest("Invalid or expired OTP");
            }

            return Ok(new { message = "OTP verified successfully" });
        }

        [HttpPost("Login_Otp")]
        public async Task<IActionResult> Login_OTP([FromBody] Login_Otp model)
        {
            //Validation OTP whit OtpService
            bool isValid = await _otpService.VerifyOtpAsync(model.PhoneNumber, model.Otp);
            if (!isValid)
            {
                return BadRequest("OTP is invalid or expired.");
            }

            //Find user by PhoneNumber
            var user = await FindByPhoneNumberAsync(model.PhoneNumber);
            if(user == null)
            {
                return NotFound("User not found.");
            }

            //create jwt token
            var token = GenerateJwtToken(user);
            return Ok(new { token = token });
        }


        #region Methods
        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
                new Claim(ClaimTypes.Name, user.FullName ?? string.Empty)
            }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        public async Task<User> FindByPhoneNumberAsync(string phoneNumber)
        {
            if (_userStore is IUserPhoneNumberStore<User> phoneNumberStore)
            {
                return await _userManager.Users.FirstOrDefaultAsync(u => u.PhoneNumber == phoneNumber);
            }

            throw new InvalidOperationException("User store does not support phone numbers.");
        }

        #endregion Methods
    }
}
