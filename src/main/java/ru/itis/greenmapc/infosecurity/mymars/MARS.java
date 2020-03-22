package ru.itis.greenmapc.infosecurity.mymars;

import java.util.Arrays;

public class MARS extends MARSAbstract {

    private final byte[] key;

    public MARS(byte[] key) {
        this.key = key;
        K = expandKey(key);
    }

    @Override
    public byte[] blockEncryption(byte[] in) {
        byte[] tmp =  new byte[in.length];
        int swap;

        int[] data = new int[in.length / 4];
        for(int i = 0; i < data.length; i ++)
            data[i] = 0;
        int off = 0;
        for(int i = 0; i <data.length; i ++){
            data[i] = (
                (in[off++] & 0xff))|
                ((in[off++] & 0xff) << 8) |
                ((in[off++] & 0xff) << 16) |
                ((in[off++] & 0xff) << 24);
        }

        int A = data[0], B = data[1], C = data[2], D = data[3];

        A = A + K[0];
        B = B + K[1];
        C = C + K[2];
        D = D + K[3];

        //FORWARD MIXING Ok!
        for(int i = 0; i < 8; i ++){
            B ^= s_box[A & HEX_255];
            B += s_box[(rotateRight(A,8) & HEX_255) + 256];
            C += s_box[rotateRight(A,16) & 0xff];
            D ^= s_box[(rotateRight(A,24) & 0xff) + 256];

            A = rotateRight(A,24);

            if(i == 1 || i == 5) A += B;
            if(i == 0 || i == 4) A += D;

            swap = A;
            A = B;
            B = C;
            C = D;
            D = swap;
        }


        //FKT
        int[] eout;
        for(int i = 0; i < 8; i ++) {

            eout = e(A, K[2 * i + 4], K[2 * i + 5]); //(ok)

            A = rotateLeft(A, 13);
            B += eout[0];
            C += eout[1];
            D ^= eout[2];

            swap = A;
            A = B;
            B = C;
            C = D;
            D = swap;
        }

        //BKT
        for (int i = 8; i < 16; i ++) {

            eout = e(A, K[2 * i + 4], K[2 * i + 5]); //(ok)

            A = rotateLeft(A, 13);
            B ^= eout[2];
            C += eout[1];
            D += eout[0];

            swap = A;
            A = B;
            B = C;
            C = D;
            D = swap;
        }

        //BACKWARD MIXING
        for (int i = 0; i < 8; i++) {

            if(i == 3 || i == 7) A -= B;
            if(i == 2 || i == 6) A -= D;

            B ^= s_box[256 + (A & 0xFF)];
            C -= s_box[rotateLeft(A, 8) & 0xFF];
            D -= s_box[256 + (rotateLeft(A, 16) & 0xFF)];
            D ^= s_box[rotateLeft(A, 24) & 0xFF];
            A = rotateLeft(A,24);

            int t = A;
            A = B;
            B = C;
            C = D;
            D = t;
        }

        A -= K[36];
        B -= K[37];
        C -= K[38];
        D -= K[39];

        data[0] = A;
        data[1] = B;
        data[2] = C;
        data[3] = D;

        for(int i = 0; i < tmp.length; i ++){
            tmp[i] = (byte)((data[i/4] >>> (i%4)*8) & 0xff);
        }

        System.out.println(Arrays.toString(tmp));
        return tmp;
    }

    @Override
    public byte[] decryptBlock(byte[] in) {
        byte[] tmp =  new byte[in.length];
        int aux;

        int[] data = new int[in.length / 4];
        for(int i = 0; i <data.length; i++)
            data[i] = 0;
        int off = 0;
        for(int i = 0;i<data.length;i++){
            data[i] = ((in[off++]&0xff)) |
                ((in[off++] & 0xff) << 8) |
                ((in[off++] & 0xff) << 16) |
                ((in[off++] & 0xff) << 24);
        }

        int A = data[0] ,B = data[1], C = data[2], D = data[3];
        A += K[36];
        B += K[37];
        C += K[38];
        D += K[39];

        for(int i = 7; i >= 0;i --){

            aux = D;
            D = C;
            C = B;
            B = A;
            A = aux;

            A = rotateRight(A,24);

            D = D ^ s_box[(rotateRight(A,8) & 0xff)];
            D = D + s_box[(rotateRight(A,16) & 0xff) + 256];
            C = C + s_box[rotateRight(A,24) & 0xff];
            B = B ^ s_box[(A & 0xff) + 256];

            if(i == 2 || i == 6) A += D;
            if(i == 3 || i == 7) A += B;

        }

        // BKT
        int[] eout;
        for(int i = 15; i >=0; i --) {
            aux = D;
            D = C;
            C = B;
            B = A;
            A = aux;

            A = rotateRight(A, 13);
            eout = e(A, K[2 * i + 4], K[2 * i + 5]);

            C = C - eout[1];

            if (i < 8) {
                B = B - eout[0];
                D = D ^ eout[2];
            } else {
                D = D - eout[0];
                B = B ^ eout[2];
            }
        }


        for(int i = 7; i >= 0; i --) {

            aux = D;
            D = C;
            C = B;
            B = A;
            A = aux;

            if(i == 0 || i == 4) A -= D;
            if(i == 1 || i == 5) A -= B;


            A = rotateLeft(A,24);

            D = D ^ s_box[(rotateRight(A,24) & 0xff) + 256];
            C = C - s_box[rotateRight(A,16) & 0xff];
            B = B - s_box[(rotateRight(A,8) & 0xff) + 256];
            B = B ^ s_box[A & 0xff];

        }

        A -= K[0];
        B -= K[1];
        C -= K[2];
        D -= K[3];

        data[0] = A;data[1] = B;data[2] = C;data[3] = D;

        for(int i = 0;i<tmp.length;i++){
            tmp[i] = (byte)((data[i/4] >>> (i%4)*8) & 0xff);
        }

        return tmp;
    }

}
