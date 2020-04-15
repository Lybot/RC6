using System;
using System.Security.Cryptography;
using System.Text;

namespace RC6
{
    public class RC6
    {
        private const int R = 20; // колличество раундов
        private static uint[] RoundKey = new uint[2 * R + 4];  // ключ раунда
        private const int W = 32; // длина машинного слова в битах
        private static byte[] MainKey; // ключ
        private const uint P32 = 0xB7E15163; // константы экспоненты золотого сечения
        private const uint Q32 = 0x9E3779B9;
        /*Генерация ключа*/
        //Конструктор с генерацией ключа
        public RC6(int keyLong)
        {
            GenerateKey(keyLong, null);
        }
        //Конструктор для запуска тестов с заранее заданным ключом
        public RC6(int keyLong, byte[] key)
        {
            GenerateKey(keyLong, key);
        }
        // Сдвиг вправо без потери
        private static uint RightShift(uint value, int shift)
        {
            return (value >> shift) | (value << (W - shift));
        }
        //Сдвиг влево без потери
        private static uint LeftShift(uint value, int shift)
        {
            return (value << shift) | (value >> (W - shift));
        }
        //Генерация main key и раундовых ключей
        private static void GenerateKey(int Long, byte[] keyCheck)
        {
            //Если main key не задан заранее используем генератор случайных ключей
            if (keyCheck == null)
            {
                AesCryptoServiceProvider aesCrypto = new AesCryptoServiceProvider //ключи самому генерировать не очень
                {
                    //Задаем размер ключа заданный в конструкторе класса
                    KeySize = Long
                };
                aesCrypto.GenerateKey();
                MainKey = aesCrypto.Key;
            }
            else MainKey = keyCheck;
            int c = 0;
            int i, j;
            //В зависимости от размера ключа выбираем на сколько блоков разбивать main key
            switch (Long)
            {
                case 128:// длина ключа
                    c = 4; // кол-во слов в ключе
                    break;
                case 192:// длина ключа
                    c = 6; // кол-во слов в ключе
                    break;
                case 256: // длина ключа
                    c = 8; // кол-во слов в ключе
                    break;
            }
            uint[] L = new uint[c];
            for (i = 0; i < c; i++)
            {
                L[i] = BitConverter.ToUInt32(MainKey, i * 4); // разбиваем ключ на слова
            }
            //Сама генерация раундовых ключей в соответствие с документацией
            RoundKey[0] = P32;
            for (i = 1; i < 2 * R + 4; i++)
                RoundKey[i] = RoundKey[i - 1] + Q32; // прибавление к раундовому ключу константу
            uint A, B; // регистры
            A = B = 0;
            i = j = 0;
            int V = 3 * Math.Max(c, 2 * R + 4);  // максимум из раундов или количества слов в ключе
            for (int s = 1; s <= V; s++)
            {
                A = RoundKey[i] = LeftShift((RoundKey[i] + A + B), 3); // сдвиг влево на 3
                B = L[j] = LeftShift((L[j] + A + B), (int)(A + B)); // сдвиг влево на a+b
                i = (i + 1) % (2 * R + 4);
                j = (j + 1) % c;
            }
        }
        // разбивает на массив байтов
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
            //Преобразование полученного текста в массив байт
            byte[] byteText = Encoding.UTF8.GetBytes(plaintext);
            int i = byteText.Length;
            while (i % 16 != 0)
                i++;
            //Создаем новый массив, кратность рамезрность которого кратна 16, так как алгоритм описывает работу с четырьмя блоками по 4 байта.
            byte[] text = new byte[i];
            //Записываем туда plaintext
            byteText.CopyTo(text, 0);
            byte[] cipherText = new byte[i];
            //Цикл по каждому блоку из 16 байт
            for (i = 0; i < text.Length; i = i + 16)
            {
                //Полученный блок из 16 байт разбиваем на 4 машинных слова(по 32 бита)
                A = BitConverter.ToUInt32(text, i);
                B = BitConverter.ToUInt32(text, i + 4);
                C = BitConverter.ToUInt32(text, i + 8);
                D = BitConverter.ToUInt32(text, i + 12);
                //Сам алгоритм шифрования в соответствии с документацией
                B = B + RoundKey[0];
                D = D + RoundKey[1];
                for (int j = 1; j <= R; j++)
                {
                    uint t = LeftShift((B * (2 * B + 1)), (int)(Math.Log(W, 2)));
                    uint u = LeftShift((D * (2 * D + 1)), (int)(Math.Log(W, 2)));
                    A = (LeftShift((A ^ t), (int)u)) + RoundKey[j * 2];
                    C = (LeftShift((C ^ u), (int)t)) + RoundKey[j * 2 + 1];
                    uint temp = A;
                    A = B;
                    B = C;
                    C = D;
                    D = temp;
                }
                A = A + RoundKey[2 * R + 2];
                C = C + RoundKey[2 * R + 3];
                //Обратное преобразование машинных слов в массив байтов
                uint[] tempWords = new uint[4] { A, B, C, D };
                byte[] block = ToArrayBytes(tempWords, 4);
                //Запись преобразованных 16 байт в массив байт шифр-текста
                block.CopyTo(cipherText, i);
            }
            return cipherText;
        }
        public byte[] DecodeRc6(byte[] cipherText)
        {
            uint A, B, C, D;
            int i;
            byte[] plainText = new byte[cipherText.Length];
            //Разбиение шифр-текста на блоки по 16 байт
            for (i = 0; i < cipherText.Length; i = i + 16)
            {
                //Разбиение блока на 4 машинных слова по 32 бита
                A = BitConverter.ToUInt32(cipherText, i);
                B = BitConverter.ToUInt32(cipherText, i + 4);
                C = BitConverter.ToUInt32(cipherText, i + 8);
                D = BitConverter.ToUInt32(cipherText, i + 12);
                //Сам процесс расшифрования в соответствии с документацией
                C = C - RoundKey[2 * R + 3];
                A = A - RoundKey[2 * R + 2];
                for (int j = R; j >= 1; j--)
                {
                    uint temp = D;
                    D = C;
                    C = B;
                    B = A;
                    A = temp;
                    uint u = LeftShift((D * (2 * D + 1)), (int)Math.Log(W, 2));
                    uint t = LeftShift((B * (2 * B + 1)), (int)Math.Log(W, 2));
                    C = RightShift((C - RoundKey[2 * j + 1]), (int)t) ^ u;
                    A = RightShift((A - RoundKey[2 * j]), (int)u) ^ t;
                }
                D = D - RoundKey[1];
                B = B - RoundKey[0];
                //Преобразование машинных слов обрано в массив байт
                uint[] tempWords = new uint[4] { A, B, C, D };
                byte[] block = ToArrayBytes(tempWords, 4);
                //Запись расшифрованных байт в массив байт расшифрованного текста
                block.CopyTo(plainText, i);
            }
            return plainText;
        }
    }
}
