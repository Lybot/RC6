using System;
using System.Text;

namespace RC6 
{
    class Program
    {
        private static bool Test()
        {
            byte[] test = { 0x8f, 0xc3, 0xa5, 0x36, 0x56, 0xb1, 0xf7, 0x78, 0xc1, 0x29, 0xdf, 0x4e, 0x98, 0x48, 0xa4, 0x1e };
            byte[] MainKey = new byte[] { 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00 };
            byte[] plaintText = { 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00 };
            string plaintTextstring = Encoding.Default.GetString(plaintText);
            RC6 kek = new RC6(128, MainKey);
            byte[] cipher = kek.EncodeRc6(plaintTextstring);
            int i=0;
            while (i < test.Length)
            {
                if (test[i] != cipher[i]) return false;
                i++;
            }

            return true;

        }
        private static bool Test2()
        {
            byte[] test = { 0x3a, 0x96, 0xf9, 0xc7, 0xf6, 0x75, 0x5c, 0xfe, 0x46, 0xf0, 0x0e, 0x3d, 0xcd, 0x5d, 0x2a, 0x3c };
            byte[] MainKey = new byte[] { 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            byte[] plaintText = { 00, 01, 02, 03, 04, 05, 06, 07, 08, 09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
            string plaintTextstring = Encoding.Default.GetString(plaintText);
            RC6 kek = new RC6(128, MainKey);
            byte[] cipher = kek.EncodeRc6(plaintTextstring);
            int i = 0;
            while (i < test.Length)
            {
                if (test[i] != cipher[i]) return false;
                i++;
            }

            return true;
        }

        private static RC6 SelectKeySize()
        {
            Console.WriteLine("Write key-size (128,192,256)");
            int Long = 0;
            try
            {
                Long = int.Parse(Console.ReadLine());
            }
            catch (Exception e)
            {
                Console.WriteLine("Not letters");
            }
            if (Long == 1)
            {
                bool success= Test();
                if(success) Console.WriteLine("GG EASY");
                else Console.WriteLine("Not easy");
            }

            if (Long == 2)
            {
                bool success = Test2();
                if (success) Console.WriteLine("GG EASY");
                else Console.WriteLine("Not easy");
            }

            if (Long == 128 || Long == 192 || Long == 256)
            {
                try
                {
                    return new RC6(Long, null);
                }
                catch (Exception e)
                {
                    Console.WriteLine(e);
                    SelectKeySize();
                }
            }
            else
            {
                Console.WriteLine("nice try");
                SelectKeySize();
            }
            return new RC6(128,null);
        }

        static void Main(string[] args)
        {
            string plainText;
            byte[] cipherText;

            RC6 rc6 = SelectKeySize();         
            Console.WriteLine("Write plain text");
            plainText = Console.ReadLine();
            try
            {
                cipherText = rc6.EncodeRc6(plainText);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
            Console.WriteLine(Encoding.UTF8.GetString(cipherText));
            try
            {
                plainText=Encoding.Default.GetString(rc6.DecodeRc6(cipherText));
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
