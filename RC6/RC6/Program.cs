using System;
using System.ComponentModel;
using System.Text;

namespace RC6
{
    class Program
    {
        private byte[] Key;
        private static void GenerateKey(int Long)
        {

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

        private string Test()
        {
            return "plaintext";
        }
        static void Main(string[] args)
        {
            string plainText;
            byte[] cipherText;
            Console.WriteLine("Write key-size (0-255)");
            short Long = Int16.Parse(Console.ReadLine());
            try
            {
                GenerateKey(Long);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            Console.WriteLine();
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
