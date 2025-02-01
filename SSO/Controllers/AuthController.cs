using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using SSO.Entity;
using SSO.ServiceModel;
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
        #endregion

        #region Constructor
        public AuthController(UserManager<User> userManager)
        {
            _userManager = userManager;
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

        [HttpPost("Login_Otp")]
        public async Task<IActionResult> Login_OTP([FromBody] Login_Otp model)
        {
            var user = await _userManager.FindByNameAsync(model.PhoneNumber);

            if (user == null)
            {
                return BadRequest("User not found");
            }

            // تولید یک کد تصادفی ۶ رقمی
            var otpCode = new Random().Next(100000, 999999).ToString();

            await _userManager.SetAuthenticationTokenAsync(user,"OTP","LoginCode",otpCode);

            // TODO: سرویس ارسال پیامک

            return Ok("OTP code sent.");
        }

        [HttpPost("verify-otp")]
        public async Task<IActionResult> VerifyOtp([FromBody] OtpVerifyRequest model)
        {
            var user = await _userManager.FindByNameAsync(model.PhoneNumber);
            if (user == null)
                return BadRequest("User not found");

            var storedOtp = await _userManager.GetAuthenticationTokenAsync(user, "OTP", "LoginCode");
            if (storedOtp != model.OtpCode)
                return Unauthorized("Invalid OTP");

            var token = GenerateJwtToken(user);
            return Ok(new { token });
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
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Name, user.FullName)
                }),
                Expires = DateTime.UtcNow.AddHours(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
            };
            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
        #endregion Methods
    }
}
