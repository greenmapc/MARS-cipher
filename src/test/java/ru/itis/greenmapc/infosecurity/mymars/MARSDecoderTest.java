package ru.itis.greenmapc.infosecurity.mymars;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import ru.itis.greenmapc.infosecurity.AbstractTest;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MARSDecoderTest extends AbstractTest {

    @Test
    public void decoderTest1() {
        var expectedResult = "00000000000000000000000000000000";
        var key = "80000000000000000000000000000000";
        var in = "B3E2AD5608AC1B6733A7CB4FDF8F9952";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void decoderTest2() {
        var expectedResult = "F94512A9B42D034EC4792204D708A69B";
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var in = "225DA2CB64B73F79069F21A5E3CB8522";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest3() {
        var in = "225DA2CB64B73F79069F21A5E3CB8522";
        var key = "CB14A1776ABBC1CDAFE7243DEF2CEA02";
        var expectedResult = "F94512A9B42D034EC4792204D708A69B";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest4() {
        var in = "DCC07B8DFB0738D6E30A22DFCF27E886";
        var key = "00000000000000000000000000000000";
        var expectedResult = "00000000000000000000000000000000";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest5() {
        var expectedResult = "00000000000000000000000000000000";
        var key = "00000000000000000000000000000000";
        var in = "DCC07B8DFB0738D6E30A22DFCF27E886";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest6() {
        var expectedResult = "4DF955AD5B398D66408D620A2B27E1A9";
        var key = "86EDF4DA31824CABEF6A4637C40B0BAB";
        var in = "A4B737340AE6D2CAFD930BA97D86129F";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest7() {
        var expectedResult = "4DF955AD5B398D66408D620A2B27E1A9";
        var key = "86EDF4DA31824CABEF6A4637C40B0BAB";
        var in = "A4B737340AE6D2CAFD930BA97D86129F";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest8() {
        var expectedResult = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        var key = "000000000000000000000000000000000000000000000000";
        var in = "97778747D60E425C2B4202599DB856FB";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest9() {
        var expectedResult = "93A953A82C10411DD158860838874D95";
        var key = "D158860838874D9500000000000000000000000000000000";
        var in = "4FA0E5F64893131712F01408D233E9F7";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest10() {
        var expectedResult = "6761C42D3E6142D2A84FBFADB383158F";
        var key = "791739A58B04581A93A953A82C10411DD158860838874D95";
        var in = "F706BC0FD97E28B6F1AF4E17D8755FFF";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest11() {
        var expectedResult = "62E45B4CF3477F1DD65063729D9ABA8F";
        var key = "0000000000000000000000000000000000000000000000000000000000000000";
        var in = "0F4B897EA014D21FBC20F1054A42F719";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }

    @Test
    public void encoderTest12() {
        var expectedResult = "1344ABA4D3C44708A8A72116D4F49384";
        var key = "FBA167983E7AEF22317CE28C02AAE1A3E8E5CC3CEDBEA82A99DBC39AD65E7227";
        var in = "458335D95EA42A9F4DCCD41AECC2390D";

        var keyBytes = hexToByte(key);
        var inBytes = hexToByte(in);

        var mars = new MARS(keyBytes);
        var result = Hex.encodeHexString(mars.decryptBlock(inBytes));

        assertEquals(expectedResult, result.toUpperCase());
    }


}
