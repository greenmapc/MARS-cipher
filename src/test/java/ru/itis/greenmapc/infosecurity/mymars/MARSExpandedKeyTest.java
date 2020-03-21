package ru.itis.greenmapc.infosecurity.mymars;

import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class MARSExpandedKeyTest extends AbstractTest {

    private static final byte[] inBytes = hexToByte("00000000000000000000000000000000");


    private MARS mars = new MARS();

    @Test
    void expandKeyTest1() throws Exception {
        var expectedKeys = List.of(
            "7a690123", "4a4cf6ee", "d1c145fd", "4a929170", "551a7316",
            "d46b4d1f", "6a68b2dd", "52a45b5f", "d99775e0", "fbec331b",
            "9879762b", "dbdb6103", "b66dfcd5", "560475c7", "897923f4",
            "cb157a67", "be38b5d6", "f5e2a20b", "db46b244", "258e03fb",
            "4e45dcc8", "38a3bf7b", "b600f7b9", "ce23f06b", "b255f1c4",
            "66fe13cb", "3fa7323b", "e5168ed7", "3c1ca161", "ac63d7fb",
            "50826e87", "87b0e657", "77f7012a", "c1e7aa83", "79d936fc",
            "56174f97", "9f8f4547", "c3901cc5", "f32a2b2e", "c604c22b"
        );

        String key = "80000000000000000000000000000000";
        var keyBytes = hexToByte(key);
        var result = mars.expandKey(keyBytes);
        assertEquals(expectedKeys, keysToStringList(result));

        var expectedEncryptionRes = "B3E2AD5608AC1B6733A7CB4FDF8F9952";
        var encResult = Hex.encodeHexString(mars.encrypt(inBytes, keyBytes));
        assertEquals(expectedEncryptionRes, encResult.toUpperCase());
    }

    @Test
    void expandKeyTest2() throws Exception {
        var expectedKeys = List.of(
            "cf784be7", "0426f341", "f9b720e1", "56319d00", "d9334c37",
            "b5bc3d47", "537983e2", "de39ff7f", "0905711b", "f94a089f",
            "acb07549", "aefd3e8f", "90902350", "d7aeb43b", "66927c4a",
            "087ba93f", "b50d26fd", "5e2c832f", "06b4a714", "88d66bdb",
            "75959004", "88f52893", "7e5829bd", "6641cb2f", "c6338d8a",
            "9e36775b", "423b4d94", "187cb2cb", "b33208e0", "1a81089f",
            "a474b6e8", "e0f09a6f", "13eaf158", "8ef9867b", "94e4467f",
            "7f4e9693", "f787318f", "dac77605", "e8958bc6", "d25f07f0"
        );

        String key = "40000000000000000000000000000000";
        var keyBytes = hexToByte(key);
        var result = mars.expandKey(keyBytes);
        assertEquals(expectedKeys, keysToStringList(result));

        var expectedEncryptionRes = "8655D5CCAF76A3A8AA09841F04689465";
        var encResult = Hex.encodeHexString(mars.encrypt(inBytes, keyBytes));
        assertEquals(expectedEncryptionRes, encResult.toUpperCase());
    }

    @Test
    void expandKeyTest3() throws Exception {
        var expectedKeys = List.of(
            "8b594e39", "84210389", "7d0a010f", "c5bcedec", "443991c6",
            "1199d927", "d2ab5705", "fea1ae5b", "55efcd0a", "4d30c827",
            "2b00c7ab", "3cb520db", "cb66b6e2", "e59ac4fb", "45541088",
            "85fb6503", "4e3f2702", "79050d27", "7e6ec87e", "a84377fb",
            "0b8db831", "b1845abb", "79f4e32a", "5f236673", "170e6ddc",
            "a3c968cf", "8c0dda77", "8dc65927", "46e520f9", "9c4128c7",
            "6a04d4e7", "eb8d46e3", "7fe38c41", "6d554423", "4eda6762",
            "012ec823", "b753dbfd", "c7083346", "58887bdf", "34705cb0"
        );

        String key = "20000000000000000000000000000000";
        var keyBytes = hexToByte(key);
        var result = mars.expandKey(keyBytes);
        assertEquals(expectedKeys, keysToStringList(result));

        var expectedEncryptionRes = "F611F21A70C0AB5FB3D52AD5E8196E09";
        var encResult = Hex.encodeHexString(mars.encrypt(inBytes, keyBytes));
        assertEquals(expectedEncryptionRes, encResult.toUpperCase());
    }

    @Test
    void expandKeyTest4() throws Exception {
        var expectedKeys = List.of(
            "c4f05dd4", "ab075239", "9a8da8da", "2291915d", "8a9dc691",
            "cbaf59cb", "e4bacd66", "a49923c3", "304f20ee", "ebd2faff",
            "33f957b1", "1d6c2783", "0cb747fc", "fb228493", "1a02f588",
            "767dcc73", "59328e57", "a56ff7af", "029e74a9", "4d06d5f3",
            "5ddfdab0", "b7192e2f", "8e9bdc72", "221d09af", "38eeaa3c",
            "78258047", "8b6e05a0", "d83a56cb", "0782d60f", "203570ab",
            "2d35213f", "6296ea4f", "b8cd39f9", "eeb3efd3", "b876ccab",
            "643a6993", "b85d404d", "bda9218d", "4e7f0ed5", "1f9515ae"
        );

        String key = "04000000000000000000000000000000";
        var keyBytes = hexToByte(key);
        var result = mars.expandKey(keyBytes);
        assertEquals(expectedKeys, keysToStringList(result));

        var expectedEncryptionRes = "FDDBC84DA51496AD1CA2B7013B93FFA8";
        var encResult = Hex.encodeHexString(mars.encrypt(inBytes, keyBytes));
        assertEquals(expectedEncryptionRes, encResult.toUpperCase());
    }

    @Test
    void expandKeyTest5() throws Exception {
        var expectedKeys = List.of(
            "c0759327", "6c420062", "6bb05e22", "17c47f42", "1021945f",
            "f71c7efb", "8f9a5fe9", "935abdbf", "f197eedb", "f44f519b",
            "7e6cb64d", "4b4721ef", "f3eaacb7", "4e6e15b7", "35e48712",
            "42ba3f5b", "52f4079c", "90f90453", "c31fcec1", "1165f963",
            "3666d048", "8e1e371b", "6a33d86c", "591f96fb", "ff07ba12",
            "ca1892db", "1968480a", "efdf0553", "41ef35bf", "0eeb6b2b",
            "0ea59e94", "728811c3", "8e4b174a", "ec6506cb", "beed228f",
            "140689f7", "18da77e8", "331a196d", "1b93546c", "1e3ad1fa"
        );

        String key = "00000000000000000000000000000001";
        var keyBytes = hexToByte(key);
        var result = mars.expandKey(keyBytes);
        assertEquals(expectedKeys, keysToStringList(result));

        var expectedEncryptionRes = "F65B8E5EAF04B33AD5FCF1B14874E059";
        var encResult = Hex.encodeHexString(mars.encrypt(inBytes, keyBytes));
        assertEquals(expectedEncryptionRes, encResult.toUpperCase());

    }


    private List<String> keysToStringList(int[] keys) {
        var res = new ArrayList<String>();
        for (int i : keys) {
            var hex = Integer.toHexString(i);
            var addZero = new StringBuilder();
            if (hex.length() < 8) {
                for (int j = 0; j < 8 - hex.length(); j ++) {
                    addZero.append("0");
                }
            }
            addZero.append(hex);
            res.add(addZero.toString());
        }
        return res;
    }
}