package humanmethod;

import java.math.BigInteger;

public class IntegerPolynomialP256 extends IntegerPolynomial {
    private static final int BITS_PER_LIMB = 26;
    private static final int NUM_LIMBS = 10;
    private static final int MAX_ADDS = 2;
    public static final BigInteger MODULUS = evaluateModulus();
    private static final long CARRY_ADD = 33554432L;
    private static final int LIMB_MASK = 67108863;

    public IntegerPolynomialP256() {
        super(26, 10, 2, MODULUS);
    }

    private static BigInteger evaluateModulus() {
        BigInteger result = BigInteger.valueOf(2L).pow(256);
        result = result.subtract(BigInteger.valueOf(2L).pow(224));
        result = result.add(BigInteger.valueOf(2L).pow(192));
        result = result.add(BigInteger.valueOf(2L).pow(96));
        result = result.subtract(BigInteger.valueOf(1L));
        return result;
    }

    protected void finalCarryReduceLast(long[] limbs) {
        long c = limbs[9] >> 22;
        limbs[9] -= c << 22;
        limbs[8] += c << 16 & 67108863L;
        limbs[9] += c >> 10;
        limbs[7] -= c << 10 & 67108863L;
        limbs[8] -= c >> 16;
        limbs[3] -= c << 18 & 67108863L;
        limbs[4] -= c >> 8;
        limbs[0] += c;
    }

    private void carryReduce(long[] r, long c0, long c1, long c2, long c3, long c4, long c5, long c6, long c7, long c8, long c9, long c10, long c11, long c12, long c13, long c14, long c15, long c16, long c17, long c18) {
        long c19 = 0L;
        c16 += c18 << 20 & 67108863L;
        c17 += c18 >> 6;
        c15 -= c18 << 14 & 67108863L;
        c16 -= c18 >> 12;
        c11 -= c18 << 22 & 67108863L;
        c12 -= c18 >> 4;
        c8 += c18 << 4 & 67108863L;
        c9 += c18 >> 22;
        c15 += c17 << 20 & 67108863L;
        c16 += c17 >> 6;
        c14 -= c17 << 14 & 67108863L;
        c15 -= c17 >> 12;
        c10 -= c17 << 22 & 67108863L;
        c11 -= c17 >> 4;
        c7 += c17 << 4 & 67108863L;
        c8 += c17 >> 22;
        c14 += c16 << 20 & 67108863L;
        c15 += c16 >> 6;
        c13 -= c16 << 14 & 67108863L;
        c14 -= c16 >> 12;
        c9 -= c16 << 22 & 67108863L;
        c10 -= c16 >> 4;
        c6 += c16 << 4 & 67108863L;
        c7 += c16 >> 22;
        c13 += c15 << 20 & 67108863L;
        c14 += c15 >> 6;
        c12 -= c15 << 14 & 67108863L;
        c13 -= c15 >> 12;
        c8 -= c15 << 22 & 67108863L;
        c9 -= c15 >> 4;
        c5 += c15 << 4 & 67108863L;
        c6 += c15 >> 22;
        c12 += c14 << 20 & 67108863L;
        c13 += c14 >> 6;
        c11 -= c14 << 14 & 67108863L;
        c12 -= c14 >> 12;
        c7 -= c14 << 22 & 67108863L;
        c8 -= c14 >> 4;
        c4 += c14 << 4 & 67108863L;
        c5 += c14 >> 22;
        c11 += c13 << 20 & 67108863L;
        c12 += c13 >> 6;
        c10 -= c13 << 14 & 67108863L;
        c11 -= c13 >> 12;
        c6 -= c13 << 22 & 67108863L;
        c7 -= c13 >> 4;
        c3 += c13 << 4 & 67108863L;
        c4 += c13 >> 22;
        c10 += c12 << 20 & 67108863L;
        c11 += c12 >> 6;
        c9 -= c12 << 14 & 67108863L;
        c10 -= c12 >> 12;
        c5 -= c12 << 22 & 67108863L;
        c6 -= c12 >> 4;
        c2 += c12 << 4 & 67108863L;
        c3 += c12 >> 22;
        c9 += c11 << 20 & 67108863L;
        c10 += c11 >> 6;
        c8 -= c11 << 14 & 67108863L;
        c9 -= c11 >> 12;
        c4 -= c11 << 22 & 67108863L;
        c5 -= c11 >> 4;
        c1 += c11 << 4 & 67108863L;
        c2 += c11 >> 22;
        c8 += c10 << 20 & 67108863L;
        c9 += c10 >> 6;
        c7 -= c10 << 14 & 67108863L;
        c8 -= c10 >> 12;
        c3 -= c10 << 22 & 67108863L;
        c4 -= c10 >> 4;
        c0 += c10 << 4 & 67108863L;
        c1 += c10 >> 22;
        c10 = 0L;
        this.carryReduce0(r, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19);
    }

    void carryReduce0(long[] r, long c0, long c1, long c2, long c3, long c4, long c5, long c6, long c7, long c8, long c9, long c10, long c11, long c12, long c13, long c14, long c15, long c16, long c17, long c18, long c19) {
        long t0 = c8 + 33554432L >> 26;
        c8 -= t0 << 26;
        c9 += t0;
        t0 = c9 + 33554432L >> 26;
        c9 -= t0 << 26;
        c10 += t0;
        c8 += c10 << 20 & 67108863L;
        c9 += c10 >> 6;
        c7 -= c10 << 14 & 67108863L;
        c8 -= c10 >> 12;
        c3 -= c10 << 22 & 67108863L;
        c4 -= c10 >> 4;
        c0 += c10 << 4 & 67108863L;
        c1 += c10 >> 22;
        t0 = c0 + 33554432L >> 26;
        c0 -= t0 << 26;
        c1 += t0;
        t0 = c1 + 33554432L >> 26;
        c1 -= t0 << 26;
        c2 += t0;
        t0 = c2 + 33554432L >> 26;
        c2 -= t0 << 26;
        c3 += t0;
        t0 = c3 + 33554432L >> 26;
        c3 -= t0 << 26;
        c4 += t0;
        t0 = c4 + 33554432L >> 26;
        c4 -= t0 << 26;
        c5 += t0;
        t0 = c5 + 33554432L >> 26;
        c5 -= t0 << 26;
        c6 += t0;
        t0 = c6 + 33554432L >> 26;
        c6 -= t0 << 26;
        c7 += t0;
        t0 = c7 + 33554432L >> 26;
        c7 -= t0 << 26;
        c8 += t0;
        t0 = c8 + 33554432L >> 26;
        c8 -= t0 << 26;
        c9 += t0;
        r[0] = c0;
        r[1] = c1;
        r[2] = c2;
        r[3] = c3;
        r[4] = c4;
        r[5] = c5;
        r[6] = c6;
        r[7] = c7;
        r[8] = c8;
        r[9] = c9;
    }

    private void carryReduce(long[] r, long c0, long c1, long c2, long c3, long c4, long c5, long c6, long c7, long c8, long c9) {
        long c10 = 0L;
        long t0 = c8 + 33554432L >> 26;
        c8 -= t0 << 26;
        c9 += t0;
        t0 = c9 + 33554432L >> 26;
        c9 -= t0 << 26;
        c10 += t0;
        c8 += c10 << 20 & 67108863L;
        c9 += c10 >> 6;
        c7 -= c10 << 14 & 67108863L;
        c8 -= c10 >> 12;
        c3 -= c10 << 22 & 67108863L;
        c4 -= c10 >> 4;
        c0 += c10 << 4 & 67108863L;
        c1 += c10 >> 22;
        t0 = c0 + 33554432L >> 26;
        c0 -= t0 << 26;
        c1 += t0;
        t0 = c1 + 33554432L >> 26;
        c1 -= t0 << 26;
        c2 += t0;
        t0 = c2 + 33554432L >> 26;
        c2 -= t0 << 26;
        c3 += t0;
        t0 = c3 + 33554432L >> 26;
        c3 -= t0 << 26;
        c4 += t0;
        t0 = c4 + 33554432L >> 26;
        c4 -= t0 << 26;
        c5 += t0;
        t0 = c5 + 33554432L >> 26;
        c5 -= t0 << 26;
        c6 += t0;
        t0 = c6 + 33554432L >> 26;
        c6 -= t0 << 26;
        c7 += t0;
        t0 = c7 + 33554432L >> 26;
        c7 -= t0 << 26;
        c8 += t0;
        t0 = c8 + 33554432L >> 26;
        c8 -= t0 << 26;
        c9 += t0;
        r[0] = c0;
        r[1] = c1;
        r[2] = c2;
        r[3] = c3;
        r[4] = c4;
        r[5] = c5;
        r[6] = c6;
        r[7] = c7;
        r[8] = c8;
        r[9] = c9;
    }

    protected void mult(long[] a, long[] b, long[] r) {
        long c0 = a[0] * b[0];
        long c1 = a[0] * b[1] + a[1] * b[0];
        long c2 = a[0] * b[2] + a[1] * b[1] + a[2] * b[0];
        long c3 = a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0];
        long c4 = a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0];
        long c5 = a[0] * b[5] + a[1] * b[4] + a[2] * b[3] + a[3] * b[2] + a[4] * b[1] + a[5] * b[0];
        long c6 = a[0] * b[6] + a[1] * b[5] + a[2] * b[4] + a[3] * b[3] + a[4] * b[2] + a[5] * b[1] + a[6] * b[0];
        long c7 = a[0] * b[7] + a[1] * b[6] + a[2] * b[5] + a[3] * b[4] + a[4] * b[3] + a[5] * b[2] + a[6] * b[1] + a[7] * b[0];
        long c8 = a[0] * b[8] + a[1] * b[7] + a[2] * b[6] + a[3] * b[5] + a[4] * b[4] + a[5] * b[3] + a[6] * b[2] + a[7] * b[1] + a[8] * b[0];
        long c9 = a[0] * b[9] + a[1] * b[8] + a[2] * b[7] + a[3] * b[6] + a[4] * b[5] + a[5] * b[4] + a[6] * b[3] + a[7] * b[2] + a[8] * b[1] + a[9] * b[0];
        long c10 = a[1] * b[9] + a[2] * b[8] + a[3] * b[7] + a[4] * b[6] + a[5] * b[5] + a[6] * b[4] + a[7] * b[3] + a[8] * b[2] + a[9] * b[1];
        long c11 = a[2] * b[9] + a[3] * b[8] + a[4] * b[7] + a[5] * b[6] + a[6] * b[5] + a[7] * b[4] + a[8] * b[3] + a[9] * b[2];
        long c12 = a[3] * b[9] + a[4] * b[8] + a[5] * b[7] + a[6] * b[6] + a[7] * b[5] + a[8] * b[4] + a[9] * b[3];
        long c13 = a[4] * b[9] + a[5] * b[8] + a[6] * b[7] + a[7] * b[6] + a[8] * b[5] + a[9] * b[4];
        long c14 = a[5] * b[9] + a[6] * b[8] + a[7] * b[7] + a[8] * b[6] + a[9] * b[5];
        long c15 = a[6] * b[9] + a[7] * b[8] + a[8] * b[7] + a[9] * b[6];
        long c16 = a[7] * b[9] + a[8] * b[8] + a[9] * b[7];
        long c17 = a[8] * b[9] + a[9] * b[8];
        long c18 = a[9] * b[9];
        this.carryReduce(r, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18);
    }

    protected void reduce(long[] a) {
        this.carryReduce(a, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]);
    }

    protected void square(long[] a, long[] r) {
        long c0 = a[0] * a[0];
        long c1 = 2L * a[0] * a[1];
        long c2 = 2L * a[0] * a[2] + a[1] * a[1];
        long c3 = 2L * (a[0] * a[3] + a[1] * a[2]);
        long c4 = 2L * (a[0] * a[4] + a[1] * a[3]) + a[2] * a[2];
        long c5 = 2L * (a[0] * a[5] + a[1] * a[4] + a[2] * a[3]);
        long c6 = 2L * (a[0] * a[6] + a[1] * a[5] + a[2] * a[4]) + a[3] * a[3];
        long c7 = 2L * (a[0] * a[7] + a[1] * a[6] + a[2] * a[5] + a[3] * a[4]);
        long c8 = 2L * (a[0] * a[8] + a[1] * a[7] + a[2] * a[6] + a[3] * a[5]) + a[4] * a[4];
        long c9 = 2L * (a[0] * a[9] + a[1] * a[8] + a[2] * a[7] + a[3] * a[6] + a[4] * a[5]);
        long c10 = 2L * (a[1] * a[9] + a[2] * a[8] + a[3] * a[7] + a[4] * a[6]) + a[5] * a[5];
        long c11 = 2L * (a[2] * a[9] + a[3] * a[8] + a[4] * a[7] + a[5] * a[6]);
        long c12 = 2L * (a[3] * a[9] + a[4] * a[8] + a[5] * a[7]) + a[6] * a[6];
        long c13 = 2L * (a[4] * a[9] + a[5] * a[8] + a[6] * a[7]);
        long c14 = 2L * (a[5] * a[9] + a[6] * a[8]) + a[7] * a[7];
        long c15 = 2L * (a[6] * a[9] + a[7] * a[8]);
        long c16 = 2L * a[7] * a[9] + a[8] * a[8];
        long c17 = 2L * a[8] * a[9];
        long c18 = a[9] * a[9];
        this.carryReduce(r, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18);
    }
}
