# MARS-cipher

<h3> Algorithm </h3>

1. Round Keys generation
- Class - [MARSAbstract](https://github.com/greenmapc/MARS-cipher/blob/master/src/main/java/ru/itis/greenmapc/infosecurity/mymars/MARSAbstract.java) <br>
- Method - protected int[] expandKey(byte[] key), where 
```
key - 16 bytes value
```

2. Block Encryption
- Class - [MARS](https://github.com/greenmapc/MARS-cipher/blob/master/src/main/java/ru/itis/greenmapc/infosecurity/mymars/MARS.java)
- Method -  public byte[] blockEncryption(byte[] in), where 
```
in - 16 bytes input
```

3. Block decryption
- Class - [MARS](https://github.com/greenmapc/MARS-cipher/blob/master/src/main/java/ru/itis/greenmapc/infosecurity/mymars/MARS.java)
- Method -  public byte[] decryptBlock(byte[] in), where 
```
in - 16 bytes cipher
```

4. CFB mode encryption
- Class - [CFBCipherMode](https://github.com/greenmapc/MARS-cipher/blob/master/src/main/java/ru/itis/greenmapc/infosecurity/mode/CFBCipherMode.java)
- Method -  public byte[] encryptWithMode(byte[] in, Function<byte[], byte[]> encrypt, byte[] initVectorC0), where <br>
```
in - 16 bytes in
encrypt - encryption function
initVectorC0 - initialization vector (open)
```
5. CFB mode decryption
Class - main/java/ru/itis/greenmapc/infosecurity/mode/CFBCipherMode
Method - public byte[] decryptWithMode(byte[] in, Function<byte[], byte[]> encrypt, byte[] initVectorC0), where <br>
```
in - 16 byte cipher
encrypt - encryption function
initVectorC0 - initialization vector (open)
```

<h3> Test </h3>

1. Expand Key test
Class - [MARSExpandedKeyTest](https://github.com/greenmapc/MARS-cipher/blob/master/src/test/java/ru/itis/greenmapc/infosecurity/mymars/MARSExpandedKeyTest.java)

2. Encryption test
Class - [MARSEncoderTest](https://github.com/greenmapc/MARS-cipher/blob/master/src/test/java/ru/itis/greenmapc/infosecurity/mymars/MARSEncoderTest.java)

3. Decryption Test
Class - [MARSDecoderTest](https://github.com/greenmapc/MARS-cipher/blob/master/src/test/java/ru/itis/greenmapc/infosecurity/mymars/MARSDecoderTest.java)

4. CFB mode Test
Class - [CFBCipherModeTest](https://github.com/greenmapc/MARS-cipher/blob/master/src/test/java/ru/itis/greenmapc/infosecurity/mode/CFBCipherModeTest.java) <br>
```
Comment: every test contain encryption and decryption, results compared
```
