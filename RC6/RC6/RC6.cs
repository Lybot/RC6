using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace RC6
{
    class RC6 // 32/20/16 - 128/192/256
    {
        private const int R = 20;
        private static uint[] RoundKey = new uint[2 * R + 4];
        private const int W = 32;
        private static byte[] MainKey;
        private const uint P32 = 0xB7E15163;
        private const uint Q32 = 0x9E3779B9;

        public RC6(int keyLong)
        {
            GenerateKey(keyLong,null);
        }
        public RC6(int keyLong, byte[] key)
        {
            GenerateKeyTest(keyLong,key);
        }
        private static uint LeftShiftTest(uint a, int n)
        {
            n &= 0x1f; /* higher rotates would not bring anything */
            return ((a << n) | (a >> (32 - n)));
        }

        private static uint RightShiftTest(uint a, int n)
        {
            n &= 0x1f; /* higher rotates would not bring anything */
            return ((a >> n) | (a << (32 - n)));
        }
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
        private static void GenerateKey(int Long, byte[] keyCheck)
        {
            if (keyCheck == null)
            {
                AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider // ключи самому генерировать не очень
                {
                    KeySize = Long
                };
                aesCrypto.GenerateKey();
                MainKey = aesCrypto.Key;
            }
            else MainKey = keyCheck;
            int c = 0;
            int i, j;
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
            uint[] L = new uint[c];
            for (i = 0; i < c; i++)
            {
                L[i] = BitConverter.ToUInt32(MainKey, i * 4);
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
                A = RoundKey[i] = LeftShift((RoundKey[i] + A + B), ShiftCount(3));
                B = L[j] = LeftShift((L[j] + A + B), ShiftCount((int)(A + B)));
                i = (i + 1) % (2 * R + 4);
                j = (j + 1) % c;
            }
        }
        private static void GenerateKeyTest(int Long, byte[] keyCheck)
        {
            if (keyCheck == null)
            {
                AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider // ключи самому генерировать не очень
                {
                    KeySize = Long
                };
                aesCrypto.GenerateKey();
                MainKey = aesCrypto.Key;
            }
            else MainKey = keyCheck;
            int c = 0;
            int i, j;
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
            uint[] L = new uint[c];
            for (i = 0; i < c; i++)
            {
                L[i] = BitConverter.ToUInt32(MainKey, i * 4);
            }
            RoundKey[0] = P32;
            for (i = 1; i < 2 * R + 4; i++)
                RoundKey[i] = RoundKey[i - 1] + Q32;
            uint A, B;
            A = B = 0;
            i = j = 0;
            int V = 3*Math.Max(c, 2 * R + 4); // useless
            for (int s = 1; s <= V; s++)
            {
                A = RoundKey[i] = LeftShiftTest((RoundKey[i] + A + B),3);
                B = L[j] = LeftShiftTest((L[j] + A + B), (int)(A + B));
                i = (i + 1) % (2 * R + 4);
                j = (j + 1) % c;
            }
        }
        private static byte[] ToArrayBytes(uint[] uints, int Long)
        {
            byte[] arrayBytes = new byte[Long * 4];
            for (int i = 0; i < Long; i++)
            {
                byte[] temp = BitConverter.GetBytes(uints[i]);
                temp.CopyTo(arrayBytes, i * 4);
            }
            return arrayBytes;
        }
        public byte[] EncodeRc6(string plaintext)
        {
            uint A, B, C, D;
            byte[] byteText = Encoding.UTF8.GetBytes(plaintext);
            int i = byteText.Length;    //
            while (i % 16 != 0)         //
                i++;                    //
            byte[] text = new byte[i]; // 
            byteText.CopyTo(text, 0);    // мб можно проще и я аут, но это первое простое что пришло в голову, чтобы добавить 0 байты до размер блока 128 бит
            byte[] cipherText = new byte[i];
            for (i = 0; i < text.Length; i = i + 16)
            {
                A = BitConverter.ToUInt32(text, i);
                B = BitConverter.ToUInt32(text, i + 4);
                C = BitConverter.ToUInt32(text, i + 8);
                D = BitConverter.ToUInt32(text, i + 12);
                B = B + RoundKey[0];
                D = D + RoundKey[1];
                for (int j = 1; j <= R; j++)
                {
                    uint t = LeftShift((B * (2 * B + 1)), ShiftCount((int)(Math.Log(W, 2))));
                    uint u = LeftShift((D * (2 * D + 1)), ShiftCount((int)(Math.Log(W, 2))));
                    A = (LeftShift((A ^ t), ShiftCount((int)u))) + RoundKey[j * 2];
                    C = (LeftShift((C ^ u), ShiftCount((int)t))) + RoundKey[j * 2 + 1];
                    uint temp = A;
                    A = B;
                    B = C;
                    C = D;
                    D = temp;
                }

                A = A + RoundKey[2 * R + 2];
                C = C + RoundKey[2 * R + 3];
                uint[] tempWords = new uint[4] { A, B, C, D };
                byte[] block = ToArrayBytes(tempWords, 4);
                block.CopyTo(cipherText, i);
            }
            return cipherText;
        }
        public byte[] DecodeRc6(byte[] cipherText)
        {
            uint A, B, C, D;
            int i;
            byte[] plainText = new byte[cipherText.Length];
            for (i = 0; i < cipherText.Length; i = i + 16)
            {
                A = BitConverter.ToUInt32(cipherText, i);
                B = BitConverter.ToUInt32(cipherText, i + 4);
                C = BitConverter.ToUInt32(cipherText, i + 8);
                D = BitConverter.ToUInt32(cipherText, i + 12);
                C = C - RoundKey[2 * R + 3];
                A = A - RoundKey[2 * R + 2];
                for (int j = R; j >= 1; j--)
                {
                    uint temp = D;
                    D = C;
                    C = B;
                    B = A;
                    A = temp;
                    uint u = LeftShift((D * (2 * D + 1)), ShiftCount((int)Math.Log(W, 2)));
                    uint t = LeftShift((B * (2 * B + 1)), ShiftCount((int)Math.Log(W, 2)));
                    C = RightShift((C - RoundKey[2 * j + 1]), ShiftCount((int)t)) ^ u;
                    A = RightShift((A - RoundKey[2 * j]), ShiftCount((int)u)) ^ t;
                }
                D = D - RoundKey[1];
                B = B - RoundKey[0];
                uint[] tempWords = new uint[4] { A, B, C, D };
                byte[] block = ToArrayBytes(tempWords, 4);
                block.CopyTo(plainText, i);
            }
            return plainText;
        }
    }
}
