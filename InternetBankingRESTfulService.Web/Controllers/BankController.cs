using System;
using System.Globalization;
using System.Linq;
using System.Text;
using InternetBankingRESTfulService.Api;
using Microsoft.AspNetCore.Mvc;

namespace InternetBankingRESTfulService.Web.Controllers
{
    [ApiController]
    public class BankController : Controller
    {
        private readonly IInternetBankingApi _internetBankingApi;

        public BankController()
        {
            _internetBankingApi = new InternetBankingApi();
        }
        [HttpGet]
        [Route("bank/api/version")]
        [Route("bank/api-version")]
        public IActionResult GetApiVersion()
        {
            return Ok(_internetBankingApi.GetApiVersion());
        }
        [Route("bank/api/calc/MD5/{value}")]
        [Route("bank/api/calc/{value}/MD5")]
        public IActionResult CalculateMD5(string value)
        {
            return Ok(_internetBankingApi.CalculateMD5(value));
        }
        [Route("bank/api/password/strong/{value}")]
        [Route("bank/api/is-password-strong/{value}")]
        public IActionResult IsPasswordStrong(string value)
        {
            return Ok(_internetBankingApi.IsPasswordStrong(value));
        }
    }
    public class InternetBankingApi : IInternetBankingApi
    {
        public string GetApiVersion()
        {
            var version = "1.0";
            return DateTime.UtcNow.ToString("yyyy.MM.dd", CultureInfo.InvariantCulture) + "." + version;
        }

        public string CalculateMD5(string value)
        {

            // Use input string to calculate MD5 hash
            using System.Security.Cryptography.MD5 md5 = System.Security.Cryptography.MD5.Create();
            byte[] inputBytes = System.Text.Encoding.ASCII.GetBytes(value);
            byte[] hashBytes = md5.ComputeHash(inputBytes);

            // Convert the byte array to hexadecimal string
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("X2"));
            }
            return sb.ToString();
        }

        public bool IsPasswordStrong(string password)
        {
            return PasswordCheck.IsStrongPassword(password);
        }
    }

    public static class PasswordCheck
    {
        public static bool IsStrongPassword(string password)
        {
            return !string.IsNullOrEmpty(password)
                   && !password.Contains(" ")
                   && HasMinimumLength(password, 8)
                && HasUpperCaseLetter(password)
                && HasLowerCaseLetter(password)
                && (HasDigit(password) || HasLowerCaseLetter(password))
                && (HasDigit(password) && HasLowerCaseLetter(password));
        }

        #region Helper Methods

        public static bool HasMinimumLength(string password, int minLength)
        {
            return password.Length >= minLength;
        }

        /// <summary>
        /// Returns TRUE if the password has at least one digit
        /// </summary>
        public static bool HasDigit(string password)
        {
            return password.Any(c => char.IsDigit(c));
        }

        /// <summary>
        /// Returns TRUE if the password has at least one special character
        /// </summary>
        public static bool HasSpecialChar(string password)
        {
            // return password.Any(c => char.IsPunctuation(c)) || password.Any(c => char.IsSeparator(c)) || password.Any(c => char.IsSymbol(c));
            return password.IndexOfAny("!@#$%^&*?_~-£().,".ToCharArray()) != -1;
        }

        /// <summary>
        /// Returns TRUE if the password has at least one uppercase letter
        /// </summary>
        public static bool HasUpperCaseLetter(string password)
        {
            return password.Any(c => char.IsUpper(c));
        }

        /// <summary>
        /// Returns TRUE if the password has at least one lowercase letter
        /// </summary>
        public static bool HasLowerCaseLetter(string password)
        {
            return password.Any(c => char.IsLower(c));
        }
        #endregion
    }
}