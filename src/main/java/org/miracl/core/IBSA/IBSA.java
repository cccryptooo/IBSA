package org.miracl.core.IBSA;


import org.miracl.core.IBSA.Utilities.HASH2;
import org.miracl.core.IBSA.Utilities.Uti;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;


public class IBSA {


    public static final int BFS = CONFIG_BIG.MODBYTES;
    public static final int BGS = CONFIG_BIG.MODBYTES;
    public static final int IBSA_OK = 0;
    public static final int IBSA_FAIL = -1;

    public static FP4[] G2_TAB;
    public static BIG order = new BIG(ROM.CURVE_Order);

    public static int init() {
        ECP2 G = ECP2.generator();
        if (G.is_infinity()) return IBSA_FAIL;
        G2_TAB = PAIR.precomp(G);
        return IBSA_OK;
    }

    /* generate key pair, private key sk, public key PK */
    public static int KeyPairGenerate_G1(byte[] PK, byte[] SK) {

        BIG sk = Uti.getRandomBig();
        sk.toBytes(SK);
        // SkToPk
        PAIR.G1mul(ECP.generator(), sk).toBytes(PK, true);

        return IBSA_OK;
    }

    public static int KeyPairGenerate_G2(byte[] PK, byte[] SK) {

        BIG sk = Uti.getRandomBig();
        sk.toBytes(SK);
        // SkToPk
        PAIR.G2mul(ECP2.generator(), sk).toBytes(PK, true);

        return IBSA_OK;
    }

    public static int DH(byte[] OPK, byte[] KSK, byte[] DT) {
        PAIR.G1mul(ECP.fromBytes(OPK), BIG.fromBytes(KSK)).toBytes(DT, true);

        return IBSA_OK;
    }

    public static int IdentityRegister(String ID, byte[] ISK, byte[] cert) throws NoSuchAlgorithmException {
        BIG omega = HASH2.ID2Zq(ID);
        BIG isk = BIG.fromBytes(ISK);
        omega.add(isk);
        omega.invmodp(order);
        PAIR.G1mul(ECP.generator(), omega).toBytes(cert, true);
        return IBSA_OK;
    }

    public static int getAnonCert(List<byte[]> AnonCert, String ID, byte[] OPK, byte[] IPK, byte[] CERT, byte[] alpha) throws NoSuchAlgorithmException {
        int G1S = BFS + 1; /* Group 1 Size - compressed */

        ECP D = ECP.fromBytes(OPK);
        ECP Cert = ECP.fromBytes(CERT);
        ECP2 S = ECP2.fromBytes(IPK);
        BIG id = HASH2.ID2Zq(ID);


        BIG r0 = Uti.getRandomBig();
        BIG r1 = Uti.getRandomBig();
        BIG r2 = Uti.getRandomBig();
        BIG r3 = Uti.getRandomBig();

        new BIG(r0).toBytes(alpha);

        ECP C1 = PAIR.G1mul(ECP.generator(), r0);

        ECP C2 = PAIR.G1mul(D, r0);
        C2.add(Cert);

        BIG x = BIG.modmul(r0, id, order);

        ECP R1 = PAIR.G1mul(ECP.generator(), r1);

        FP12 R2 = Uti.getPair(PAIR.G1mul(C2, r3), ECP2.generator());
        FP12 pair2 = Uti.getPair(PAIR.G1mul(D, r1), S);
        pair2.inverse();
        FP12 pair3 = Uti.getPair(PAIR.G1mul(D, r2), ECP2.generator());
        pair3.inverse();
        R2.mul(pair2);
        R2.mul(pair3);

        ECP R3 = PAIR.G1mul(C1, r3);
        R3.sub(PAIR.G1mul(ECP.generator(), r2));
        byte[] CC1 = new byte[G1S];
        byte[] CC2 = new byte[G1S];
        C1.toBytes(CC1, true);
        C2.toBytes(CC2, true);

        byte[] rr1 = new byte[BGS];
        byte[] rr2 = new byte[BGS];
        byte[] rr3 = new byte[BGS];
        byte[] cc = new byte[BGS];

        BIG c = HASH2.Oracle2Zq(C1.toString() + C2.toString() + R1.toString() + R2.toString() + R3.toString());

        c.toBytes(cc);

        r1.add(BIG.modmul(c, r0, order));
        r2.add(BIG.modmul(c, x, order));
        r3.add(BIG.modmul(c, id, order));
        r1.mod(order);
        r2.mod(order);
        r3.mod(order);

        r1.toBytes(rr1);
        r2.toBytes(rr2);
        r3.toBytes(rr3);

        AnonCert.set(0, CC1);
        AnonCert.set(1, CC2);
        AnonCert.set(2, cc);
        AnonCert.set(3, rr1);
        AnonCert.set(4, rr2);
        AnonCert.set(5, rr3);
        return IBSA_OK;
    }


    public static int AnonymousJoin(List<byte[]> AnonCert, byte[] KSK, byte[] OPK, byte[] IPK, byte[] SID) throws
            NoSuchAlgorithmException {
        ECP C1 = ECP.fromBytes(AnonCert.get(0));
        ECP C2 = ECP.fromBytes(AnonCert.get(1));

        ECP D = ECP.fromBytes(OPK);
        ECP2 S = ECP2.fromBytes(IPK);

        BIG c = BIG.fromBytes(AnonCert.get(2));
        BIG va = BIG.fromBytes(AnonCert.get(3));

        BIG vb = BIG.fromBytes(AnonCert.get(4));
        BIG vc = BIG.fromBytes(AnonCert.get(5));

        ECP R1 = PAIR.G1mul(ECP.generator(), va);
        R1.sub(PAIR.G1mul(C1, c));

        FP12 R2 = Uti.getPair(PAIR.G1mul(C2, vc), ECP2.generator());
        FP12 pair1 = Uti.getPair(PAIR.G1mul(D, va), S);
        pair1.inverse();
        FP12 pair2 = Uti.getPair(PAIR.G1mul(D, vb), ECP2.generator());
        pair2.inverse();
        FP12 pair3 = Uti.getPair(PAIR.G1mul(ECP.generator(), c), ECP2.generator());
        pair3.inverse();
        FP12 pair4 = Uti.getPair(PAIR.G1mul(C2, c), S);

        R2.mul(pair1);
        R2.mul(pair2);
        R2.mul(pair3);
        R2.mul(pair4);

        ECP R3 = PAIR.G1mul(C1, vc);
        R3.sub(PAIR.G1mul(ECP.generator(), vb));

        BIG big = HASH2.Oracle2Zq(C1.toString() + C2.toString() + R1.toString() + R2.toString() + R3.toString());
        if (BIG.comp(big, c) == 0) {
            PAIR.G1mul(C2, BIG.fromBytes(KSK)).toBytes(SID, true);
            return IBSA_OK;
        } else {
            return IBSA_FAIL;
        }

    }

    public static void AddressGenerate(String ID, byte[] IPK, byte[] KPK, byte[] OPK, byte[] ADDR1,
                                       byte[] ADDR2, byte[] ADDR3) throws NoSuchAlgorithmException {
        ECP D = ECP.fromBytes(OPK);
        ECP2 S = ECP2.fromBytes(IPK);
        ECP2 T = ECP2.fromBytes(KPK);
        BIG rnd = Uti.getRandomBig();
        BIG id = HASH2.ID2Zq(ID);

        BIG beta = HASH2.Gt2Zq(Uti.getPair(PAIR.G1mul(ECP.generator(), rnd), T).toString());

        PAIR.G1mul(ECP.generator(), beta).toBytes(ADDR1, true);

        ECP C2 = PAIR.G1mul(D, beta);
        C2.add(PAIR.G1mul(ECP.generator(), id));
        C2.toBytes(ADDR2, true);
        S.add(PAIR.G2mul(ECP2.generator(), id));
        PAIR.G2mul(S, rnd).toBytes(ADDR3, true);
    }

    public static int core_sign(byte[] SIGN1, byte[][] SIGN2, byte[] SIGN3, byte[] M, byte[] SID, byte[] ADDR1,
                                byte[] ADDR2, byte[] ADDR3, String ID, byte[] KPK, byte[] OPK) throws NoSuchAlgorithmException {
        ECP D = ECP.fromBytes(OPK);
        ECP Sid = ECP.fromBytes(SID);
        ECP C1 = ECP.fromBytes(ADDR1);
        ECP C2 = ECP.fromBytes(ADDR2);
        ECP2 C3 = ECP2.fromBytes(ADDR3);
        ECP2 T = ECP2.fromBytes(KPK);
        BIG id = HASH2.ID2Zq(ID);
        //check

        BIG beta = HASH2.Gt2Zq(Uti.getPair(Sid, C3).toString());

        if (PAIR.G1mul(ECP.generator(), beta).equals(C1)) {
            ECP CX = PAIR.G1mul(D, beta);
            CX.add(PAIR.G1mul(ECP.generator(), id));
            if (CX.equals(C2)) {
                BIG r0 = Uti.getRandomBig();
                BIG r1 = Uti.getRandomBig();
                BIG r2 = Uti.getRandomBig();
                BIG r3 = Uti.getRandomBig();
                ECP C0 = PAIR.G1mul(Sid, r0);
                C0.toBytes(SIGN1, true);
                ECP R1 = PAIR.G1mul(ECP.generator(), r1);

                ECP R2 = PAIR.G1mul(D, r1);
                R2.add(PAIR.G1mul(ECP.generator(), r2));

                FP12 R3 = Uti.getPair(PAIR.G1mul(ECP.generator(), r3), T);
                FP12 pair = Uti.getPair(PAIR.G1mul(C0, r2), ECP2.generator());
                pair.inverse();
                R3.mul(pair);
                R3.toBytes(SIGN3);

                BIG c = HASH2.Oracle2Zq(M + C0.toString() + C1.toString() + C2.toString() + C3.toString() + R1.toString() + R2.toString() + R3.toString());
                c.toBytes(SIGN2[0]);
                r1.add(BIG.modmul(c, beta, order));
                r2.add(BIG.modmul(c, id, order));
                r3.add(BIG.modmul(c, r0, order));
                r1.mod(order);
                r2.mod(order);
                r3.mod(order);
                r1.toBytes(SIGN2[1]);
                r2.toBytes(SIGN2[2]);
                r3.toBytes(SIGN2[3]);

                return IBSA_OK;

            } else {
                return IBSA_FAIL;
            }

        } else {
            return IBSA_FAIL;
        }


    }

    public static int core_verify(byte[] SIGN1, byte[][] SIGN2, byte[] M, byte[] ADDR1, byte[] ADDR2,
                                  byte[] ADDR3, byte[] IPK, byte[] OPK, byte[] KPK) throws NoSuchAlgorithmException {
        ECP D = ECP.fromBytes(OPK);
        ECP C0 = ECP.fromBytes(SIGN1);
        ECP C1 = ECP.fromBytes(ADDR1);
        ECP C2 = ECP.fromBytes(ADDR2);
        ECP2 C3 = ECP2.fromBytes(ADDR3);
        ECP2 T = ECP2.fromBytes(KPK);
        ECP2 S = ECP2.fromBytes(IPK);

        BIG c = BIG.fromBytes(SIGN2[0]);
        BIG r1 = BIG.fromBytes(SIGN2[1]);
        BIG r2 = BIG.fromBytes(SIGN2[2]);
        BIG r3 = BIG.fromBytes(SIGN2[3]);

        ECP R1 = PAIR.G1mul(ECP.generator(), r1);
        R1.sub(PAIR.G1mul(C1, c));

        ECP R2 = PAIR.G1mul(D, r1);
        R2.sub(PAIR.G1mul(C2, c));
        R2.add(PAIR.G1mul(ECP.generator(), r2));

        FP12 R3 = Uti.getPair(PAIR.G1mul(C0, c), S);
        R3.inverse();
        FP12 pair1 = Uti.getPair(PAIR.G1mul(C0, r2), ECP2.generator());
        pair1.inverse();
        FP12 pair2 = Uti.getPair(PAIR.G1mul(ECP.generator(), r3), T);
        R3.mul(pair1);
        R3.mul(pair2);

        BIG big = HASH2.Oracle2Zq(M + C0.toString() + C1.toString() + C2.toString() + C3.toString() + R1.toString() + R2.toString() + R3.toString());

        if (BIG.comp(big, c) == 0) {
            return IBSA_OK;
        } else {
            return IBSA_FAIL;
        }
    }

    public static int batch_verify(byte[][] SIGN1, byte[][][] SIGN2, byte[][] SIGN3, byte[][] M, byte[][] ADDR1, byte[][] ADDR2,
                                   byte[][] ADDR3, byte[] IPK, byte[] OPK, byte[] KPK) throws NoSuchAlgorithmException {
        ECP D = ECP.fromBytes(OPK);
        ECP2 T = ECP2.fromBytes(KPK);
        ECP2 S = ECP2.fromBytes(IPK);

        ECP C0 = new ECP();
        ECP C1 = new ECP();
        ECP C2 = new ECP();
        ECP2 C3 = new ECP2();

        ECP R1 = new ECP();
        ECP R2 = new ECP();
        FP12 R3 = new FP12();

        BIG c = new BIG();
        BIG r1 = new BIG();
        BIG r2 = new BIG();
        BIG r3 = new BIG();

        FP12[] R3s = new FP12[SIGN3.length];
        ECP[] P1s = new ECP[SIGN3.length];
        ECP[] P2s = new ECP[SIGN3.length];
        ECP[] P3s = new ECP[SIGN3.length];
        BIG rnd = new BIG();
        BIG rnd_c = new BIG();
        BIG rnd_2 = new BIG();
        BIG rnd_3 = new BIG();
        for (int i = 0; i < SIGN3.length; i++) {
            R3 = FP12.fromBytes(SIGN3[i]);

            C0 = ECP.fromBytes(SIGN1[i]);
            C1 = ECP.fromBytes(ADDR1[i]);
            C2 = ECP.fromBytes(ADDR2[i]);
            C3 = ECP2.fromBytes(ADDR3[i]);

            c = BIG.fromBytes(SIGN2[i][0]);
            r1 = BIG.fromBytes(SIGN2[i][1]);
            r2 = BIG.fromBytes(SIGN2[i][2]);
            r3 = BIG.fromBytes(SIGN2[i][3]);


            R1 = PAIR.G1mul(ECP.generator(), r1);
            R1.sub(PAIR.G1mul(C1, c));

            R2 = PAIR.G1mul(D, r1);
            R2.sub(PAIR.G1mul(C2, c));
            R2.add(PAIR.G1mul(ECP.generator(), r2));

            BIG big = HASH2.Oracle2Zq(M[i] + C0.toString() + C1.toString() + C2.toString() + C3.toString() + R1.toString() + R2.toString() + R3.toString());
            if (BIG.comp(big, c) != 0) {
                return IBSA_FAIL;
            } else {
                rnd = Uti.getRandomBig();
                rnd_c = BIG.modmul(rnd, c, order);
                rnd_2 = BIG.modmul(rnd, r2, order);
                rnd_3 = BIG.modmul(rnd, r3, order);
                R3s[i] = PAIR.GTpow(R3, rnd);
                P1s[i] = PAIR.G1mul(C0, rnd_c);
                P2s[i] = PAIR.G1mul(C0, rnd_2);
                P3s[i] = PAIR.G1mul(ECP.generator(), rnd_3);
            }
        }

        for (int i = 1; i < R3s.length; i++) {
            R3s[1].mul(R3s[i]);
            P1s[1].add(P1s[i]);
            P2s[1].add(P2s[i]);
            P3s[1].add(P3s[i]);
        }

        R3 = Uti.getPair(P1s[1], S);
        R3.inverse();
        FP12 pair1 = Uti.getPair(P2s[1], ECP2.generator());
        pair1.inverse();
        FP12 pair2 = Uti.getPair(P3s[1], T);
        R3.mul(pair1);
        R3.mul(pair2);

        if (R3.equals(R3s[1])) {
            return IBSA_OK;
        } else {
            return IBSA_FAIL;
        }


    }

    public static int trace(byte[] ADDR1, byte[] ADDR2, byte[] ADDR3,
                            byte[] OSK, byte[] OPK, byte[] PI1, byte[] PI2, String ID) throws NoSuchAlgorithmException {
        ECP C1 = ECP.fromBytes(ADDR1);
        ECP C2 = ECP.fromBytes(ADDR2);
        ECP2 C3 = ECP2.fromBytes(ADDR3);
        ECP opk = ECP.fromBytes(OPK);
        BIG osk = BIG.fromBytes(OSK);
        BIG x = Uti.getRandomBig();
        ECP X = PAIR.G1mul(C1, x);
        BIG c = HASH2.Oracle2Zq(C1.toString() + C2.toString() + C3.toString() + X.toString() + opk.toString() + ID);

        C2.sub(PAIR.G1mul(C1, osk));
        ECP ecp = PAIR.G1mul(ECP.generator(), HASH2.ID2Zq(ID));

        if (ecp.equals(C2)) {
            x.add(BIG.modmul(c, osk, order));
            x.mod(order);
            x.toBytes(PI1);
            X.toBytes(PI2, true);
            return IBSA_OK;
        } else {
            return IBSA_FAIL;
        }
    }

    public static int traceVer(byte[] ADDR1, byte[] ADDR2, byte[] ADDR3, byte[] OPK, byte[] PI1, byte[] PI2, String ID) throws NoSuchAlgorithmException {
        ECP C1 = ECP.fromBytes(ADDR1);
        ECP C2 = ECP.fromBytes(ADDR2);
        ECP2 C3 = ECP2.fromBytes(ADDR3);
        ECP opk = ECP.fromBytes(OPK);
        BIG s = BIG.fromBytes(PI1);
        ECP X = ECP.fromBytes(PI2);

        BIG c = HASH2.Oracle2Zq(C1.toString() + C2.toString() + C3.toString() + X.toString() + opk.toString() + ID);

        C2.sub(PAIR.G1mul(ECP.generator(), HASH2.ID2Zq(ID)));
        C2 = PAIR.G1mul(C2, c);
        C2.add(X);

        ECP ecp = PAIR.G1mul(C1, s);
        if (ecp.equals(C2)) {
            return IBSA_OK;
        } else {
            return IBSA_FAIL;
        }
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        int G1S = BFS + 1; /* Group 1 Size - compressed */
        int G2S = 2 * BFS + 1; /* Group 2 Size - compressed */
        int G3S = 12 * BFS + 1; /* Group 3 Size*/

        byte[] IPK = new byte[G2S];
        byte[] KPK = new byte[G2S];
        byte[] OPK = new byte[G1S];
        byte[] DT = new byte[G1S];

        byte[] ISK = new byte[BGS];
        byte[] KSK = new byte[BGS];
        byte[] OSK = new byte[BGS];

        byte[] SID = new byte[G1S];
        byte[] Cert = new byte[G1S];

        List<byte[]> AnonCert = new ArrayList<>();
        byte[] AnonCert1 = new byte[G1S];
        byte[] AnonCert2 = new byte[G1S];
        byte[] AnonCert3 = new byte[BGS];
        byte[] AnonCert4 = new byte[BGS];
        byte[] AnonCert5 = new byte[BGS];
        byte[] AnonCert6 = new byte[BGS];
        AnonCert.add(AnonCert1);
        AnonCert.add(AnonCert2);
        AnonCert.add(AnonCert3);
        AnonCert.add(AnonCert4);
        AnonCert.add(AnonCert5);
        AnonCert.add(AnonCert6);

        byte[] ADDR1 = new byte[G1S];
        byte[] ADDR2 = new byte[G1S];
        byte[] ADDR3 = new byte[G2S];

        byte[] SIG1 = new byte[G1S];
        byte[][] SIG2 = new byte[4][BGS];
        byte[] SIG3 = new byte[G3S];

        KeyPairGenerate_G1(OPK, OSK);
        KeyPairGenerate_G2(IPK, ISK);
        KeyPairGenerate_G2(KPK, KSK);
        DH(OPK, KSK, DT);
        String ID = Uti.getRandomString();
        byte[] M = Uti.getRandomString().getBytes();

        IdentityRegister(ID, ISK, Cert);

        byte[] alpha = new byte[BGS];
        getAnonCert(AnonCert, ID, OPK, IPK, Cert, alpha);

        ECP cert = ECP.fromBytes(Cert);
        ECP2 check = PAIR.G2mul(ECP2.generator(), HASH2.ID2Zq(ID));
        check.add(ECP2.fromBytes(IPK));
        FP12 pair1 = Uti.getPair(cert, check);
        pair1.equals(Uti.getPair(ECP.generator(), ECP2.generator()));


        AnonymousJoin(AnonCert, KSK, OPK, IPK, SID);

        ECP sid = ECP.fromBytes(SID);
        BIG Alpha = BIG.fromBytes(alpha);
        sid.sub(PAIR.G1mul(ECP.fromBytes(DT), Alpha));

        FP12 pair2 = Uti.getPair(sid, check);
        pair2.equals(Uti.getPair(ECP.generator(), ECP2.fromBytes(KPK)));
        sid.toBytes(SID, true);

        AddressGenerate(ID, IPK, KPK, OPK, ADDR1, ADDR2, ADDR3);
        int flag = core_sign(SIG1, SIG2, SIG3, M, SID, ADDR1, ADDR2, ADDR3, ID, KPK, OPK);
        flag += core_verify(SIG1, SIG2, M, ADDR1, ADDR2, ADDR3, IPK, OPK, KPK);

        byte[] PI1 = new byte[BGS];
        byte[] PI2 = new byte[G1S];

        flag += trace(ADDR1, ADDR2, ADDR3, OSK, OPK, PI1, PI2, ID);
        System.out.println(flag);
        flag += traceVer(ADDR1, ADDR2, ADDR3, OPK, PI1, PI2, ID);
        System.out.println(flag);
    }
}