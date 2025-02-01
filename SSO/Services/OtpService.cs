using StackExchange.Redis;

namespace SSO.Services
{
    public class OtpService
    {
        #region Properties
        private readonly IConnectionMultiplexer _redis;
        private readonly IDatabase _db;
        private readonly Random _random = new();
        #endregion

        #region Constroctures
        public OtpService(IConnectionMultiplexer redis)
        {
            _redis = redis;
            _db = _redis.GetDatabase();
        }
        #endregion

        public async Task<string> GenerateOtpAsync (string phoneNumber)
        {
            string otp = _random.Next(100000,999999).ToString();
            string key = $"otp:{phoneNumber}";

            await _db.StringSetAsync(key, otp, TimeSpan.FromMinutes(5)); //otp code valid for 5 minutes
            return otp;
        }

        public async Task<bool> VerifyOtpAsync(string phoneNumber, string otpCode)
        {
            string key = $"otp:{phoneNumber}";
            var storedOtp = await _db.StringGetAsync(key);

            if(storedOtp.HasValue && storedOtp.ToString() == otpCode)
            {
                await _db.KeyDeleteAsync(key);// after used otp code delet otp code
                return true;
            }
            return false;
        }
    }
}
