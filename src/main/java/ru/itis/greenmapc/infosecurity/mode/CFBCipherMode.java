package ru.itis.greenmapc.infosecurity.mode;

import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.function.Function;
import java.util.logging.Logger;

@NoArgsConstructor
public class CFBCipherMode {

    private Logger log = Logger.getLogger("CFB Encryption Mode");

    public byte[] encryptWithMode(byte[] in, Function<byte[], byte[]> encrypt, byte[] initVectorC0) {
        log.info(Arrays.toString(initVectorC0) + " INIT VECTOR");

        var blocks = getBlocks(in);
        byte[] result = new byte[blocks.size() * 16];

        byte[] prevC = initVectorC0;
        int count = 0;
        for (byte[] block : blocks) {
            prevC = arrayXor(encrypt.apply(prevC), block);
            int j = 0;
            for (int i = count * 16; i < (count + 1) * 16; i ++) {
                result[i] = prevC[j];
                j ++;
            }
            count ++;
        }

        return result;
    }

    public byte[] decryptWithMode(byte[] in, Function<byte[], byte[]> encrypt, byte[] initVectorC0) {
        log.info(Arrays.toString(initVectorC0) + " INIT VECTOR");

        var blocks = getBlocks(in);
        byte[] result = new byte[blocks.size() * 16];

        byte[] prevC = initVectorC0;
        int count = 0;
        for (byte[] block : blocks) {
            prevC = arrayXor(block, encrypt.apply(prevC));
            int j = 0;
            for (int i = count * 16; i < (count + 1) * 16; i ++) {
                result[i] = prevC[j];
                j ++;
            }
            count ++;
            prevC =  block;
        }

        return deletePadding(result);
    }

    private byte[] arrayXor(byte[] c, byte[] p) {
        byte[] res = new byte[16];
        int i = 0;
        for (byte b : p)
            res[i] = (byte) (b ^ c[i++]);
        return res;
    }

    private List<byte[]> getBlocks(byte[] in) {
        List<byte[]> blocks = new ArrayList<>();
        final int BLOCK_SIZE = 16;
        int mod = in.length % BLOCK_SIZE;
        int additionalLength =  mod != 0 ? BLOCK_SIZE - mod : 0;

        byte[] padding = new byte[additionalLength];
        if (mod != 0) {
            padding[0] = (byte) 0x80;
        }
        byte[] block = new byte[BLOCK_SIZE];


        int count = 0;

        int i;
        for (i = 0; i < in.length + additionalLength; i++) {
            if (i > 0 && i % BLOCK_SIZE == 0) {
                blocks.add(Arrays.copyOf(block, block.length));
            }
            if (i < in.length)
                block[i % BLOCK_SIZE] = in[i];
            else{
                block[i % BLOCK_SIZE] = padding[count % BLOCK_SIZE];
                count++;
            }
        }
        blocks.add(Arrays.copyOf(block, block.length));

        return blocks;
    }

    private static byte[] deletePadding(byte[] input) {
        int count = 0;

        int i = input.length - 1;
        while (i >= 0 && input[i] == 0) {
            count++;
            i--;
        }

        if (count != 0 && count != 16) {
            byte[] tmp = new byte[input.length - count - 1];
            System.arraycopy(input, 0, tmp, 0, tmp.length);
            return tmp;
        } else {
            return input;
        }
    }

}
