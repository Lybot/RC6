# RC6
realize RC6 with c#
<br/>
https://web.archive.org/web/20070101014400/http://theory.lcs.mit.edu/~rivest/rc6.pdf
![](https://upload.wikimedia.org/wikipedia/commons/c/ce/RC6_Cryptography_Algorithm.JPG)
<br/>
` R  `- колличество раундов <br/>
`RoundKey `- раундовый ключ <br/>
` W ` - длина машинного слова в битах <br/>
`MainKey `- ключ <br/>
` P32 и Q32` - константы на основе экспоненты и золотого сечения <br/>
<br/>
`uint RightShift(uint value, int shift)` - побитовый сдвиг вправо  <br/>
`uint LeftShift(uint value, int shift)` - побитовый сдвиг влево <br/>
`int ShiftCount(int count)` - количество сдвигов <br/>
`void GenerateKey(int Long, byte[] keyCheck) `- генрирует ключ с помощью aes, делит побитово ключ  <br/>
  `с ` -количество слов в ключе; <br/>
  `A B` - регистры; <br/>
` void GenerateKeyTest(int Long, byte[] keyCheck) `- генерирует тестовый ключ <br/>
`byte[] ToArrayBytes(uint[] uints, int Long) `- конвертирует в битовый масив <br/>
` byte[] EncodeRc6(string plaintext)` - шифрование  <br/>
  `A B C D` - части текста <br/>
`byte[] EncodeRc6Test(string plaintext)`- тестовое шифрование  <br/>
`byte[] DecodeRc6Test(byte[] cipherText)` -дешифрование <br/>
