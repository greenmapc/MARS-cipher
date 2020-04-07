package ru.itis.greenmapc.infosecurity.mode;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import ru.itis.greenmapc.infosecurity.AbstractTest;
import ru.itis.greenmapc.infosecurity.mymars.MARS;

import java.math.BigInteger;
import java.time.LocalDateTime;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

class CFBCipherModeTest extends AbstractTest {

    @Test
    void applyMode1() {
        var key = "80000000000000000000000000000000";
        var in = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var cfbEncryptionMode = new CFBCipherMode();
        var mars = new MARS(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(cfbEncryptionMode.encryptWithMode(inBytes, mars::blockEncryption, initVector));
        var decResult = Hex.encodeHexString(cfbEncryptionMode.decryptWithMode(hexToByte(encResult), mars::blockEncryption, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    @Test
    void applyMode2() {
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var in = "F94512A9B42D034EC4792204D708A69B";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var cfbEncryptionMode = new CFBCipherMode();
        var mars = new MARS(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(cfbEncryptionMode.encryptWithMode(inBytes, mars::blockEncryption, initVector));
        var decResult = Hex.encodeHexString(cfbEncryptionMode.decryptWithMode(hexToByte(encResult), mars::blockEncryption, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    @Test
    void applyMode3() {
        var key = "00000000000000000000000000000000";
        var in = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var cfbEncryptionMode = new CFBCipherMode();
        var mars = new MARS(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(cfbEncryptionMode.encryptWithMode(inBytes, mars::blockEncryption, initVector));
        var decResult = Hex.encodeHexString(cfbEncryptionMode.decryptWithMode(hexToByte(encResult), mars::blockEncryption, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    @Test
    void applyMode5() {
        var key = "00000000000000000000000000000000";
        var in = "0000000000000000000000000000000000000000000000000000000000800000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var cfbEncryptionMode = new CFBCipherMode();
        var mars = new MARS(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(cfbEncryptionMode.encryptWithMode(inBytes, mars::blockEncryption, initVector));
        var decResult = Hex.encodeHexString(cfbEncryptionMode.decryptWithMode(hexToByte(encResult), mars::blockEncryption, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    @Test
    void applyMode6() {
        var key = "00000000000000000000000000000000";
        var in = "0000000000000000000000000000000000000000080";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var cfbEncryptionMode = new CFBCipherMode();
        var mars = new MARS(keyBytes);
        var initVector = generateInitVector();

        var encResult = cfbEncryptionMode.encryptWithMode(inBytes, mars::blockEncryption, initVector);
        var encHexResult = Hex.encodeHexString(encResult);
        var decResult = cfbEncryptionMode.decryptWithMode(hexToByte(encHexResult), mars::blockEncryption, initVector);
        var decHexResult = Hex.encodeHexString(decResult);
        assertNotNull(encResult);
        assertNotNull(decResult);
        assertArrayEquals(inBytes, decResult);
    }

    @Test
    void applyMode4() {
        var key = "10000000000000000000000000000000";
        var in = "000000000000000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var cfbEncryptionMode = new CFBCipherMode();
        var mars = new MARS(keyBytes);
        var initVector = generateInitVector();

        var encResult = Hex.encodeHexString(cfbEncryptionMode.encryptWithMode(inBytes, mars::blockEncryption, initVector));
        var decResult = Hex.encodeHexString(cfbEncryptionMode.decryptWithMode(hexToByte(encResult), mars::blockEncryption, initVector));

        assertNotNull(encResult);
        assertNotNull(decResult);
        assertEquals(in, decResult.toUpperCase());
    }

    public byte[] generateInitVector() {
        byte[] result = new byte[16];
        var time = LocalDateTime.now();
        var weekday = time.getDayOfYear();
        var hours = time.getHour();
        var minutes = time.getMinute();
        var seconds = time.getSecond();

        var first4Bytes = BigInteger.valueOf(weekday).toByteArray();
        var second4Bytes = BigInteger.valueOf(hours).toByteArray();
        var third4Bytes = BigInteger.valueOf(minutes).toByteArray();
        var fourth4Bytes = BigInteger.valueOf(seconds).toByteArray();

        System.arraycopy(first4Bytes, 0, result, 4 - first4Bytes.length % 4, first4Bytes.length);
        System.arraycopy(second4Bytes, 0, result, 8 - second4Bytes.length % 4, second4Bytes.length);
        System.arraycopy(third4Bytes, 0, result, 12 - third4Bytes.length % 4, third4Bytes.length);
        System.arraycopy(fourth4Bytes, 0, result, 16 - fourth4Bytes.length % 4, fourth4Bytes.length);

        return result;
    }
}