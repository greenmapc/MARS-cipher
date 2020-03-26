package ru.itis.greenmapc.infosecurity.mymars;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;
import ru.itis.greenmapc.infosecurity.AbstractTest;

import java.io.BufferedReader;
import java.io.FileReader;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class MARSEncoderByFileTest extends AbstractTest {

    @Test
    public void test128key() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("key128.txt"));
        var key = hexToByte(br.readLine().substring(4));

        while(br.ready()) {
            br.readLine();
            br.readLine();
            var in = hexToByte(br.readLine().substring(3));
            var expectedResult = br.readLine().substring(3);

            var mars = new MARS(key);
            var result = Hex.encodeHexString(mars.blockEncryption(in));

            assertEquals(expectedResult, result.toUpperCase());
        }
    }

    @Test
    public void test192key() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("key192.txt"));
        var key = hexToByte(br.readLine().substring(4));

        while(br.ready()) {
            br.readLine();
            br.readLine();
            var in = hexToByte(br.readLine().substring(3));
            var expectedResult = br.readLine().substring(3);

            var mars = new MARS(key);
            var result = Hex.encodeHexString(mars.blockEncryption(in));

            assertEquals(expectedResult, result.toUpperCase());
        }
    }

    @Test
    public void test256key() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("key256.txt"));
        var key = hexToByte(br.readLine().substring(4));

        while(br.ready()) {
            br.readLine();
            br.readLine();
            var in = hexToByte(br.readLine().substring(3));
            var expectedResult = br.readLine().substring(3);

            var mars = new MARS(key);
            var result = Hex.encodeHexString(mars.blockEncryption(in));

            assertEquals(expectedResult, result.toUpperCase());
        }
    }
}
