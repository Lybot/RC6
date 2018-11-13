# RC6
realize RC6 with c#

### R - колличество раундов 
### RoundKey - раундовый ключ
### W - длина машинного слова в битах
### MainKey - ключ
### P32 и Q32 - константы на основе экспоненты и золотого сечения

### uint RightShift(uint value, int shift) - побитовый сдвиг вправо 
### uint LeftShift(uint value, int shift) - побитовый сдвиг влево
### int ShiftCount(int count) - количество сдвигов
### void GenerateKey(int Long, byte[] keyCheck) - генрирует ключ с помощью aes, делит побитово ключ 
  с количество слов в ключе;
  A B - регистры;
### void GenerateKeyTest(int Long, byte[] keyCheck) - генерирует тестовый ключ
### byte[] ToArrayBytes(uint[] uints, int Long) - конвертирует в битовый масив
### byte[] EncodeRc6(string plaintext) - шифрование 
  A B C D - части текста
### byte[] EncodeRc6Test(string plaintext)- тестовое шифрование 
### byte[] DecodeRc6Test(byte[] cipherText) -дешифрование
