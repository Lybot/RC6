# RC6
realize RC6 with c#
<br/>
https://web.archive.org/web/20070101014400/http://theory.lcs.mit.edu/~rivest/rc6.pdf
![](https://upload.wikimedia.org/wikipedia/commons/c/ce/RC6_Cryptography_Algorithm.JPG)
<br/>
` R  `- колличество раундов <br/>
`RoundKey[] `- массив раундовых ключей (2R+4) <br/>
` W ` - длина машинного слова в битах <br/>
`MainKey `- ключ <br/>
` P32 и Q32` - константы на основе экспоненты и золотого сечения <br/>
<br/>
`uint RightShift(uint value, int shift)` - побитовый сдвиг вправо  <br/>
`uint LeftShift(uint value, int shift)` - побитовый сдвиг влево <br/>
`void GenerateKey(int Long, byte[] keyCheck) `- генрирует ключ с помощью aes, генерирует раундовые ключи <br/>
  `с ` -количество слов в ключе; <br/>
  `A B` - регистры; <br/>
`byte[] ToArrayBytes(uint[] uints, int Long) `- конвертирует 4 машинных слова в 16 байт <br/>
`byte[] EncodeRc6(string plaintext)` - шифрование  <br/>
`byte[] DecodeRc6(string plaintext)` - расшифрование  <br/>
  `A B C D` - части текста <br/>
