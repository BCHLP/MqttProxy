using System;
using System.Security.Cryptography;
using System.Text;

namespace MqttClient
{
    public class TotpAuthenticator
    {
        private readonly byte[] _secretKey;
        private readonly int _digits;
        private readonly int _timeStepSeconds;
        private readonly string _hashAlgorithm;

        public TotpAuthenticator(string base32Secret, int digits = 6, int timeStepSeconds = 30, string hashAlgorithm = "SHA1")
        {
            _secretKey = Base32Decode(base32Secret);
            _digits = digits;
            _timeStepSeconds = timeStepSeconds;
            _hashAlgorithm = hashAlgorithm;
        }

        public TotpAuthenticator(byte[] secretKey, int digits = 6, int timeStepSeconds = 30, string hashAlgorithm = "SHA1")
        {
            _secretKey = secretKey;
            _digits = digits;
            _timeStepSeconds = timeStepSeconds;
            _hashAlgorithm = hashAlgorithm;
        }

        /// <summary>
        /// Generate TOTP code for current time
        /// </summary>
        public string GenerateCode()
        {
            return GenerateCode(DateTime.UtcNow);
        }

        /// <summary>
        /// Generate TOTP code for specific time
        /// </summary>
        public string GenerateCode(DateTime timestamp)
        {
            var timeCounter = GetTimeCounter(timestamp);
            return GenerateCodeFromCounter(timeCounter);
        }

        /// <summary>
        /// Validate TOTP code with tolerance for time drift
        /// </summary>
        public bool ValidateCode(string code, int toleranceSteps = 1)
        {
            return ValidateCode(code, DateTime.UtcNow, toleranceSteps);
        }

        /// <summary>
        /// Validate TOTP code for specific time with tolerance
        /// </summary>
        public bool ValidateCode(string code, DateTime timestamp, int toleranceSteps = 1)
        {
            var baseTimeCounter = GetTimeCounter(timestamp);

            // Check current time and surrounding time steps for clock drift tolerance
            for (int i = -toleranceSteps; i <= toleranceSteps; i++)
            {
                var testCounter = baseTimeCounter + i;
                var expectedCode = GenerateCodeFromCounter(testCounter);

                if (string.Equals(code, expectedCode, StringComparison.Ordinal))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>
        /// Get remaining seconds until next code generation
        /// </summary>
        public int GetRemainingSeconds()
        {
            var currentTime = DateTime.UtcNow;
            var timeCounter = GetTimeCounter(currentTime);
            var nextTimeStep = (timeCounter + 1) * _timeStepSeconds;
            var nextTimestamp = DateTimeOffset.FromUnixTimeSeconds(nextTimeStep).DateTime;

            return (int)(nextTimestamp - currentTime).TotalSeconds;
        }

        private long GetTimeCounter(DateTime timestamp)
        {
            var unixTimestamp = ((DateTimeOffset)timestamp).ToUnixTimeSeconds();
            return unixTimestamp / _timeStepSeconds;
        }

        private string GenerateCodeFromCounter(long counter)
        {
            var counterBytes = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counterBytes);
            }

            byte[] hash;
            using (var hmac = CreateHmacAlgorithm())
            {
                hmac.Key = _secretKey;
                hash = hmac.ComputeHash(counterBytes);
            }

            // Dynamic truncation
            int offset = hash[hash.Length - 1] & 0x0F;
            int binaryCode = ((hash[offset] & 0x7F) << 24) |
                            ((hash[offset + 1] & 0xFF) << 16) |
                            ((hash[offset + 2] & 0xFF) << 8) |
                            (hash[offset + 3] & 0xFF);

            int otp = binaryCode % (int)Math.Pow(10, _digits);
            return otp.ToString().PadLeft(_digits, '0');
        }

        private HMAC CreateHmacAlgorithm()
        {
            return _hashAlgorithm.ToUpper() switch
            {
                "SHA1" => new HMACSHA1(),
                "SHA256" => new HMACSHA256(),
                "SHA512" => new HMACSHA512(),
                _ => throw new ArgumentException($"Unsupported hash algorithm: {_hashAlgorithm}")
            };
        }

        /// <summary>
        /// Generate a random Base32 secret for device pairing
        /// </summary>
        public static string GenerateSecret(int length = 32)
        {
            var random = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(random);
            }
            return Base32Encode(random);
        }

        /// <summary>
        /// Generate QR code URI for manual device setup
        /// </summary>
        public string GetQRCodeUri(string issuer, string account)
        {
            var secret = Base32Encode(_secretKey);
            return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(account)}?" +
                   $"secret={secret}&issuer={Uri.EscapeDataString(issuer)}&algorithm={_hashAlgorithm}&digits={_digits}&period={_timeStepSeconds}";
        }

        // Base32 encoding/decoding for secret key handling
        private static string Base32Encode(byte[] data)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            var result = new StringBuilder();
            int buffer = 0;
            int bitsLeft = 0;

            foreach (byte b in data)
            {
                buffer = (buffer << 8) | b;
                bitsLeft += 8;

                while (bitsLeft >= 5)
                {
                    result.Append(alphabet[(buffer >> (bitsLeft - 5)) & 0x1F]);
                    bitsLeft -= 5;
                }
            }

            if (bitsLeft > 0)
            {
                result.Append(alphabet[(buffer << (5 - bitsLeft)) & 0x1F]);
            }

            return result.ToString();
        }

        private static byte[] Base32Decode(string encoded)
        {
            const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
            encoded = encoded.ToUpper().Replace(" ", "").Replace("-", "");

            var result = new System.Collections.Generic.List<byte>();
            int buffer = 0;
            int bitsLeft = 0;

            foreach (char c in encoded)
            {
                int value = alphabet.IndexOf(c);
                if (value < 0) continue;

                buffer = (buffer << 5) | value;
                bitsLeft += 5;

                if (bitsLeft >= 8)
                {
                    result.Add((byte)(buffer >> (bitsLeft - 8)));
                    bitsLeft -= 8;
                }
            }

            return result.ToArray();
        }
    }
}

