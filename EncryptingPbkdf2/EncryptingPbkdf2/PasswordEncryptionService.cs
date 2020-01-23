using System;
using System.Security.Cryptography;

namespace EncryptingPbkdf2
{
    public static class PasswordEncryptionService
    {
        public const int Pbkdf2Iterations = 1000;

        public static string EncryptingPassword(string password)
        {
            var cryptoProvider = new RNGCryptoServiceProvider();

            byte[] salt = new byte[24];

            cryptoProvider.GetBytes(salt);

            var hash = GetPbkdf2Bytes(password, salt, Pbkdf2Iterations, 20);

            return Pbkdf2Iterations + ":" + Convert.ToBase64String(salt) + ":" + Convert.ToBase64String(hash);
        }

        public static bool MatchPasswords(string password, string refPassword)
        {
            char[] delimiter = { ':' };

            var split = refPassword.Split(delimiter);

            var iterations = Int32.Parse(split[0]);

            var salt = Convert.FromBase64String(split[1]);

            var hash = Convert.FromBase64String(split[2]);

            var testHash = GetPbkdf2Bytes(password, salt, iterations, hash.Length);

            return SlowEquals(hash, testHash);
        }

        private static bool SlowEquals(byte[] hash, byte[] testHash)
        {
            var diff = (uint)hash.Length ^ (uint)testHash.Length;

            for (int i = 0; i < hash.Length && i < testHash.Length; i++)
            {
                diff |= (uint)(hash[i] ^ testHash[i]);
            }

            return diff == 0;
        }

        private static byte[] GetPbkdf2Bytes(string password, byte[] salt, int iterations, int outputBytes)
        {
            var pbkdf2 = new Rfc2898DeriveBytes(password, salt);

            pbkdf2.IterationCount = iterations;

            return pbkdf2.GetBytes(outputBytes);
        }
    }
}
