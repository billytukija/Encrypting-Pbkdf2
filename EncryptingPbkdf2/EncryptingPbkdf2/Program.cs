using System;

namespace EncryptingPbkdf2
{
    class Program
    {
        static void Main(string[] args)
        {
            var pwd = PasswordEncryptionService.EncryptingPassword("billy@@grazzy");

            Console.WriteLine("Encripted password" + pwd);
        }
    }
}
