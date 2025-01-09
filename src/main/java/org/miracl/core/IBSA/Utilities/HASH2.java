package org.miracl.core.IBSA.Utilities;

import org.miracl.core.HMAC;
import org.miracl.core.IBSA.*;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HASH2 {
    static int ceil(int a, int b) {
        return (((a) - 1) / (b) + 1);
    }

    static BIG q = new BIG(ROM.Modulus);

    static FP[] hash_to_field(int hash, int hlen, byte[] DST, byte[] M, int ctr) {

        int nbq = q.nbits();
        int L = ceil(nbq + CONFIG_CURVE.AESKEY * 8, 8);
        FP[] u = new FP[ctr];
        byte[] fd = new byte[L];

        byte[] OKM = HMAC.XMD_Expand(hash, hlen, L * ctr, DST, M);
        for (int i = 0; i < ctr; i++) {
            for (int j = 0; j < L; j++)
                fd[j] = OKM[i * L + j];
            u[i] = new FP(DBIG.fromBytes(fd).ctmod(q, 8 * L - nbq));
        }

        return u;
    }


    public static BIG ID2Zq(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("identityCertification||2025".getBytes());
        byte[] hashBytes = md.digest(input.getBytes());

        long[] result = new long[7];
        int hashIndex = 0;
        for (int i = 0; i < result.length; i++) {
            long value = 0;
            for (int j = 0; j < 8; j++) {
                if (hashIndex >= hashBytes.length) {
                    hashIndex = 0;
                }
                value |= ((long) (hashBytes[hashIndex++] & 0xFF)) << (8 * j);
            }
            // 确保是正整数
            if (value < 0) {
                value &= 0x7FFFFFFFFFFFFFFFL;
            }
            result[i] = value;
        }
        BIG big = new BIG(result);
        big.mod(q);
        return big;
    }

    public static BIG Oracle2Zq(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("Challenge||2025".getBytes());
        byte[] hashBytes = md.digest(input.getBytes());
        long[] result = new long[7];
        int hashIndex = 0;
        for (int i = 0; i < result.length; i++) {
            long value = 0;
            for (int j = 0; j < 8; j++) {
                if (hashIndex >= hashBytes.length) {
                    hashIndex = 0;
                }
                value |= ((long) (hashBytes[hashIndex++] & 0xFF)) << (8 * j);
            }
            // 确保是正整数
            if (value < 0) {
                value &= 0x7FFFFFFFFFFFFFFFL;
            }
            result[i] = value;
        }
        BIG big = new BIG(result);
        big.mod(q);
        return big;
    }

    public static BIG Gt2Zq(String input) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update("elliptic curve||2025".getBytes());
        byte[] hashBytes = md.digest(input.getBytes());
        long[] result = new long[7];
        int hashIndex = 0;
        for (int i = 0; i < result.length; i++) {
            long value = 0;
            for (int j = 0; j < 8; j++) {
                if (hashIndex >= hashBytes.length) {
                    hashIndex = 0;
                }
                value |= ((long) (hashBytes[hashIndex++] & 0xFF)) << (8 * j);
            }
            // 确保是正整数
            if (value < 0) {
                value &= 0x7FFFFFFFFFFFFFFFL;
            }
            result[i] = value;
        }
        BIG big = new BIG(result);
        big.mod(q);
        return big;
    }


}
