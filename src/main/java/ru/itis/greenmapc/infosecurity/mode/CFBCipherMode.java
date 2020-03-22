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

        byte[] prevC = initVectorC0;
        for (byte[] block : getBlocks(in)) {
            prevC = arrayXor(encrypt.apply(prevC), block);
        }

        return prevC;
    }

    public byte[] decryptWithMode(byte[] in, Function<byte[], byte[]> encrypt, byte[] initVectorC0) {
        log.info(Arrays.toString(initVectorC0) + " INIT VECTOR");

        byte[] prevC = initVectorC0;
        for (byte[] block : getBlocks(in)) {
            prevC = arrayXor(block, encrypt.apply(prevC));
        }

        return prevC;
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
        int deficit = in.length % BLOCK_SIZE;
        int additionalLength =  deficit != 0 ? BLOCK_SIZE - deficit : 0;

        byte[] padding = new byte[additionalLength];
        if (deficit != 0) {
            padding[0] = (byte) 0x80;
        }
        byte[] block = new byte[BLOCK_SIZE];


        int count = 0;

        int i;
        for (i = 0; i < in.length + additionalLength; i++) {
            if (i > 0 && i % BLOCK_SIZE == 0) {
                blocks.add(block);
            }
            if (i < in.length)
                block[i % BLOCK_SIZE] = in[i];
            else{
                block[i % BLOCK_SIZE] = padding[count % BLOCK_SIZE];
                count++;
            }
        }
        blocks.add(block);

        return blocks;
    }

}
