using System;
using System.ComponentModel;
using System.ComponentModel.Design;
using System.Security.Cryptography;
using System.Text;

namespace RC6
{
    class Program
    {
        private static byte[] Key;
        private static void GenerateKey(int Long)
        {
            AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider // ключи самому генерировать не очень
            {
                KeySize = Long
            };
            aesCrypto.GenerateKey();
            Key = aesCrypto.Key;
            string topkek = Encoding.Default.GetString(aesCrypto.Key);
            Console.WriteLine(topkek); // все равно помойку выводит
        }
        private static byte[] EncodeRc6(string plaintext)
        {
            byte[] kek = System.Text.Encoding.UTF8.GetBytes(plaintext);
            return kek;
        }

        private static string DecodeRc6(byte[] ciphertext)
        {
            string kek = Encoding.UTF8.GetString(ciphertext);
            return kek;
        }

        private static void Test()
        {
            byte[] test = {0x8f, 0xc3, 0xa5, 0x36, 0x56, 0xb1, 0xf7, 0x78, 0xc1, 0x29, 0xdf, 0x4e, 0x98, 0x48};
            Key = new byte[] {00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00};
            byte[] plaintText = { 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00 };
            string plaintTextstring = Encoding.UTF8.GetString(plaintText);
            byte[] cipher = EncodeRc6(plaintTextstring);
            if (test==cipher)
                Console.WriteLine("gg easy");
            
        }
        private static void SelectKeySize()
        {
            Console.WriteLine("Write key-size (128,192.256)");
            short Long = Int16.Parse(Console.ReadLine());
            if (Long == 1)
            {
                Test();
            }
            if (Long !=128 || Long!=192 || Long !=256)
            {
                Console.WriteLine("Don't be autist");
                SelectKeySize();
            }
            try
            {
                GenerateKey(Long);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                SelectKeySize();
            }
        }
        static void Main(string[] args)
        {
            string plainText;
            byte[] cipherText;
            SelectKeySize();
            Console.WriteLine("Write plain text");
            plainText = Console.ReadLine();
            try
            {
                cipherText = EncodeRc6(plainText);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            Console.WriteLine(cipherText);
            try
            {
                plainText = DecodeRc6(cipherText);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            Console.WriteLine(plainText);
            Console.ReadKey();
        }
    }
}
