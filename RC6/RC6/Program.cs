using System;
using System.ComponentModel;
using System.ComponentModel.Design;
using System.Security.Cryptography;
using System.Text;

namespace RC6
{
    class Program
    {
        private const int R=20;
        private static uint[] RoundKey = new uint[2*R+42];
        private const int W = 32;
        private static byte[] MainKey;
        private const uint P32 = 0xB7E15163;
        private const uint Q32 = 0x9E3779B9;
        private static uint RightShift(uint value, int shift)
        {
            return (value >> shift) | (value << (W - shift));
        }
        private static uint LeftShift(uint value, int shift)
        {
            return (value << shift) | (value >> (W - shift));
        }
        private static int ShiftCount(int count)
        {
            var nLgw = (int)(Math.Log(W) / Math.Log(2.0));
            count = count << (W - nLgw);
            count = count >> (W - nLgw);
            return count;
        }
        private static void GenerateKey(int Long)
        {
            AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider // ключи самому генерировать не очень
            {
                KeySize = Long
            };
            aesCrypto.GenerateKey();
            MainKey = aesCrypto.Key;         
            int c=0;
            int i,j;
            switch (Long)
            {
                case 128:
                    c = 4;
                    break;
                case 192:
                    c = 6;
                    break;
                case 256:
                    c = 8;
                    break;
            }
            uint[] L= new uint[c];
            for (i = 0; i < c; i++)
            {
                L[i] = BitConverter.ToUInt32(MainKey,i*4);
            }
            RoundKey[0] = P32;
            for (i = 1; i < 2 * R + 4; i++)
                RoundKey[i] = RoundKey[i - 1] + Q32;
            uint A, B;
            A = B = 0;
            i = j = 0;
            int V = Math.Max(c, 2 * R + 4); // useless
            for (int s = 1; s <= V; s++)
            {
                A = RoundKey[i] = LeftShift((RoundKey[i] + A + B),ShiftCount(3));
                B = L[j] = LeftShift(L[j] + A + B,ShiftCount((int)(A+B)));
                i = (i + 1) % (2*R+4);
                j = (j + 1) % c;
            }
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
            MainKey = new byte[] {00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00};
            byte[] plaintText = {00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00};
            string plaintTextstring = Encoding.UTF8.GetString(plaintText);
            byte[] cipher = EncodeRc6(plaintTextstring);
            if (test==cipher)
                Console.WriteLine("gg easy");
            
        }
        private static void SelectKeySize()
        {
            Console.WriteLine("Write key-size (128,192,256)");
            int Long=0;
            try
            {
                Long = int.Parse(Console.ReadLine());
            }
            catch (Exception e)
            {
                Console.WriteLine("100% aut");
            }
            if (Long == 1)
            {
                Test();
            }
            if (Long ==128 || Long==192 || Long ==256)
            {
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
            else
            {
                Console.WriteLine("Don't be autist");
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
