package ru.itis.greenmapc.infosecurity.mymars;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import ru.itis.greenmapc.infosecurity.AbstractTest;

import java.math.BigInteger;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MARSEncoderTest extends AbstractTest {

    @Test
    public void encoderTest1() {
        var expectedResult = "B3E2AD5608AC1B6733A7CB4FDF8F9952";
        var key = "80000000000000000000000000000000";
        var in = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.blockEncryption(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest2() {
        var expectedResult = "33CAFFBDDC7F1DDA0F9C15FA2F30E2FF";
        var key = "00000000000000000000000000000000";
        var in = "DCC07B8DFB0738D6E30A22DFCF27E886";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.blockEncryption(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest3() {
        var expectedResult = "225DA2CB64B73F79069F21A5E3CB8522";
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var in = "F94512A9B42D034EC4792204D708A69B";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.blockEncryption(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest4() {
        var expectedResult = "DCC07B8DFB0738D6E30A22DFCF27E886";
        var key = "00000000000000000000000000000000";
        var in = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.blockEncryption(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    private byte[] generateInitVector() {
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
