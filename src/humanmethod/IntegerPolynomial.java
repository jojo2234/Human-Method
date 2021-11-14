package humanmethod;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;


public abstract class IntegerPolynomial implements IntegerFieldModuloP {
    protected static final BigInteger TWO = BigInteger.valueOf(2L);
    protected final int numLimbs;
    private final BigInteger modulus;
    protected final int bitsPerLimb;
    private final long[] posModLimbs;
    private final int maxAdds;

    protected abstract void reduce(long[] var1);

    protected void multByInt(long[] a, long b) {
        for(int i = 0; i < a.length; ++i) {
            a[i] *= b;
        }

        this.reduce(a);
    }

    protected abstract void mult(long[] var1, long[] var2, long[] var3);

    protected abstract void square(long[] var1, long[] var2);

    IntegerPolynomial(int bitsPerLimb, int numLimbs, int maxAdds, BigInteger modulus) {
        this.numLimbs = numLimbs;
        this.modulus = modulus;
        this.bitsPerLimb = bitsPerLimb;
        this.maxAdds = maxAdds;
        this.posModLimbs = this.setPosModLimbs();
    }

    private long[] setPosModLimbs() {
        long[] result = new long[this.numLimbs];
        this.setLimbsValuePositive(this.modulus, result);
        return result;
    }

    protected int getNumLimbs() {
        return this.numLimbs;
    }

    public int getMaxAdds() {
        return this.maxAdds;
    }

    public BigInteger getSize() {
        return this.modulus;
    }

    public IntegerPolynomial.ImmutableElement get0() {
        return new IntegerPolynomial.ImmutableElement(false);
    }

    public IntegerPolynomial.ImmutableElement get1() {
        return new IntegerPolynomial.ImmutableElement(true);
    }

    public IntegerPolynomial.ImmutableElement getElement(BigInteger v) {
        return new IntegerPolynomial.ImmutableElement(v);
    }

    public SmallValue getSmallValue(int value) {
        int maxMag = 1 << this.bitsPerLimb - 1;
        if (Math.abs(value) >= maxMag) {
            throw new IllegalArgumentException("max magnitude is " + maxMag);
        } else {
            return new IntegerPolynomial.Limb(value);
        }
    }

    protected void encode(ByteBuffer buf, int length, byte highByte, long[] result) {
        int numHighBits = 32 - Integer.numberOfLeadingZeros(highByte);
        int numBits = 8 * length + numHighBits;
        int requiredLimbs = (numBits + this.bitsPerLimb - 1) / this.bitsPerLimb;
        if (requiredLimbs > this.numLimbs) {
            long[] temp = new long[requiredLimbs];
            this.encodeSmall(buf, length, highByte, temp);
            System.arraycopy(temp, 0, result, 0, result.length);
        } else {
            this.encodeSmall(buf, length, highByte, result);
        }

    }

    protected void encodeSmall(ByteBuffer buf, int length, byte highByte, long[] result) {
        int limbIndex = 0;
        long curLimbValue = 0L;
        int bitPos = 0;

        for(int i = 0; i < length; ++i) {
            long curV = (long)(buf.get() & 255);
            if (bitPos + 8 >= this.bitsPerLimb) {
                int bitsThisLimb = this.bitsPerLimb - bitPos;
                curLimbValue += (curV & (long)(255 >> 8 - bitsThisLimb)) << bitPos;
                result[limbIndex++] = curLimbValue;
                curLimbValue = curV >> bitsThisLimb;
                bitPos = 8 - bitsThisLimb;
            } else {
                curLimbValue += curV << bitPos;
                bitPos += 8;
            }
        }

        if (highByte != 0) {
            long curV = (long)(highByte & 255);
            if (bitPos + 8 >= this.bitsPerLimb) {
                int bitsThisLimb = this.bitsPerLimb - bitPos;
                curLimbValue += (curV & (long)(255 >> 8 - bitsThisLimb)) << bitPos;
                result[limbIndex++] = curLimbValue;
                curLimbValue = curV >> bitsThisLimb;
            } else {
                curLimbValue += curV << bitPos;
            }
        }

        if (limbIndex < result.length) {
            result[limbIndex++] = curLimbValue;
        }

        Arrays.fill(result, limbIndex, result.length, 0L);
        this.postEncodeCarry(result);
    }

    protected void encode(byte[] v, int offset, int length, byte highByte, long[] result) {
        ByteBuffer buf = ByteBuffer.wrap(v, offset, length);
        buf.order(ByteOrder.LITTLE_ENDIAN);
        this.encode(buf, length, highByte, result);
    }

    protected void postEncodeCarry(long[] v) {
        this.reduce(v);
    }

    public IntegerPolynomial.ImmutableElement getElement(byte[] v, int offset, int length, byte highByte) {
        long[] result = new long[this.numLimbs];
        this.encode(v, offset, length, highByte, result);
        return new IntegerPolynomial.ImmutableElement(result, 0);
    }

    protected BigInteger evaluate(long[] limbs) {
        BigInteger result = BigInteger.ZERO;

        for(int i = limbs.length - 1; i >= 0; --i) {
            result = result.shiftLeft(this.bitsPerLimb).add(BigInteger.valueOf(limbs[i]));
        }

        return result.mod(this.modulus);
    }

    protected long carryValue(long x) {
        return x + (long)(1 << this.bitsPerLimb - 1) >> this.bitsPerLimb;
    }

    protected void carry(long[] limbs, int start, int end) {
        for(int i = start; i < end; ++i) {
            long carry = this.carryOut(limbs, i);
            limbs[i + 1] += carry;
        }

    }

    protected void carry(long[] limbs) {
        this.carry(limbs, 0, limbs.length - 1);
    }

    protected long carryOut(long[] limbs, int index) {
        long carry = this.carryValue(limbs[index]);
        limbs[index] -= carry << this.bitsPerLimb;
        return carry;
    }

    private void setLimbsValue(BigInteger v, long[] limbs) {
        this.setLimbsValuePositive(v, limbs);
        this.carry(limbs);
    }

    protected void setLimbsValuePositive(BigInteger v, long[] limbs) {
        BigInteger mod = BigInteger.valueOf((long)(1 << this.bitsPerLimb));

        for(int i = 0; i < limbs.length; ++i) {
            limbs[i] = v.mod(mod).longValue();
            v = v.shiftRight(this.bitsPerLimb);
        }

    }

    protected abstract void finalCarryReduceLast(long[] var1);

    protected void finalReduce(long[] limbs) {
        int smallerNonNegative;
        for(smallerNonNegative = 0; smallerNonNegative < 2; ++smallerNonNegative) {
            this.finalCarryReduceLast(limbs);
            long carry = 0L;

            for(int i = 0; i < this.numLimbs - 1; ++i) {
                limbs[i] += carry;
                carry = limbs[i] >> this.bitsPerLimb;
                limbs[i] -= carry << this.bitsPerLimb;
            }

            int var10001 = this.numLimbs - 1;
            limbs[var10001] += carry;
        }

        smallerNonNegative = 1;
        long[] smaller = new long[this.numLimbs];

        for(int i = this.numLimbs - 1; i >= 0; --i) {
            smaller[i] = limbs[i] - this.posModLimbs[i];
            smallerNonNegative *= (int)(smaller[i] >> 63) + 1;
        }

        conditionalSwap(smallerNonNegative, limbs, smaller);
    }

    protected void decode(long[] v, byte[] dst, int offset, int length) {
        int nextLimbIndex = 0;
        nextLimbIndex = nextLimbIndex + 1;
        long curLimbValue = v[nextLimbIndex];
        int bitPos = 0;

        for(int i = 0; i < length; ++i) {
            int dstIndex = i + offset;
            if (bitPos + 8 >= this.bitsPerLimb) {
                dst[dstIndex] = (byte)((int)curLimbValue);
                curLimbValue = 0L;
                if (nextLimbIndex < v.length) {
                    curLimbValue = v[nextLimbIndex++];
                }

                int bitsAdded = this.bitsPerLimb - bitPos;
                int bitsLeft = 8 - bitsAdded;
                dst[dstIndex] = (byte)((int)((long)dst[dstIndex] + ((curLimbValue & (long)(255 >> bitsAdded)) << bitsAdded)));
                curLimbValue >>= bitsLeft;
                bitPos = bitsLeft;
            } else {
                dst[dstIndex] = (byte)((int)curLimbValue);
                curLimbValue >>= 8;
                bitPos += 8;
            }
        }

    }

    protected void addLimbs(long[] a, long[] b, long[] dst) {
        for(int i = 0; i < dst.length; ++i) {
            dst[i] = a[i] + b[i];
        }

    }

    protected static void conditionalAssign(int set, long[] a, long[] b) {
        int maskValue = 0 - set;

        for(int i = 0; i < a.length; ++i) {
            long dummyLimbs = (long)maskValue & (a[i] ^ b[i]);
            a[i] ^= dummyLimbs;
        }

    }

    protected static void conditionalSwap(int swap, long[] a, long[] b) {
        int maskValue = 0 - swap;

        for(int i = 0; i < a.length; ++i) {
            long dummyLimbs = (long)maskValue & (a[i] ^ b[i]);
            a[i] ^= dummyLimbs;
            b[i] ^= dummyLimbs;
        }

    }

    protected void limbsToByteArray(long[] limbs, byte[] result) {
        long[] reducedLimbs = (long[])limbs.clone();
        this.finalReduce(reducedLimbs);
        this.decode(reducedLimbs, result, 0, result.length);
    }

    protected void addLimbsModPowerTwo(long[] limbs, long[] other, byte[] result) {
        long[] reducedOther = (long[])other.clone();
        long[] reducedLimbs = (long[])limbs.clone();
        this.finalReduce(reducedOther);
        this.finalReduce(reducedLimbs);
        this.addLimbs(reducedLimbs, reducedOther, reducedLimbs);
        long carry = 0L;

        for(int i = 0; i < this.numLimbs; ++i) {
            reducedLimbs[i] += carry;
            carry = reducedLimbs[i] >> this.bitsPerLimb;
            reducedLimbs[i] -= carry << this.bitsPerLimb;
        }

        this.decode(reducedLimbs, result, 0, result.length);
    }

    class Limb implements SmallValue {
        int value;

        Limb(int value) {
            this.value = value;
        }
    }

    class ImmutableElement extends IntegerPolynomial.Element implements ImmutableIntegerModuloP {
        protected ImmutableElement(BigInteger v) {
            super(v);
        }

        protected ImmutableElement(boolean v) {
            super(v);
        }

        protected ImmutableElement(long[] limbs, int numAdds) {
            super(limbs, numAdds);
        }

        public IntegerPolynomial.ImmutableElement fixed() {
            return this;
        }
    }

    protected class MutableElement extends IntegerPolynomial.Element implements MutableIntegerModuloP {
        protected MutableElement(long[] limbs, int numAdds) {
            super(limbs, numAdds);
        }

        public IntegerPolynomial.ImmutableElement fixed() {
            return IntegerPolynomial.this.new ImmutableElement((long[])this.limbs.clone(), this.numAdds);
        }

        public void conditionalSet(IntegerModuloP b, int set) {
            IntegerPolynomial.Element other = (IntegerPolynomial.Element)b;
            IntegerPolynomial.conditionalAssign(set, this.limbs, other.limbs);
            this.numAdds = other.numAdds;
        }

        public void conditionalSwapWith(MutableIntegerModuloP b, int swap) {
            IntegerPolynomial.MutableElement other = (IntegerPolynomial.MutableElement)b;
            IntegerPolynomial.conditionalSwap(swap, this.limbs, other.limbs);
            int numAddsTemp = this.numAdds;
            this.numAdds = other.numAdds;
            other.numAdds = numAddsTemp;
        }

        public IntegerPolynomial.MutableElement setValue(IntegerModuloP v) {
            IntegerPolynomial.Element other = (IntegerPolynomial.Element)v;
            System.arraycopy(other.limbs, 0, this.limbs, 0, other.limbs.length);
            this.numAdds = other.numAdds;
            return this;
        }

        public IntegerPolynomial.MutableElement setValue(byte[] arr, int offset, int length, byte highByte) {
            IntegerPolynomial.this.encode(arr, offset, length, highByte, this.limbs);
            this.numAdds = 0;
            return this;
        }

        public IntegerPolynomial.MutableElement setValue(ByteBuffer buf, int length, byte highByte) {
            IntegerPolynomial.this.encode(buf, length, highByte, this.limbs);
            this.numAdds = 0;
            return this;
        }

        public IntegerPolynomial.MutableElement setProduct(IntegerModuloP genB) {
            IntegerPolynomial.Element b = (IntegerPolynomial.Element)genB;
            IntegerPolynomial.this.mult(this.limbs, b.limbs, this.limbs);
            this.numAdds = 0;
            return this;
        }

        public IntegerPolynomial.MutableElement setProduct(SmallValue v) {
            int value = ((IntegerPolynomial.Limb)v).value;
            IntegerPolynomial.this.multByInt(this.limbs, (long)value);
            this.numAdds = 0;
            return this;
        }

        public IntegerPolynomial.MutableElement setSum(IntegerModuloP genB) {
            IntegerPolynomial.Element b = (IntegerPolynomial.Element)genB;
            if (this.isSummand() && b.isSummand()) {
                for(int i = 0; i < this.limbs.length; ++i) {
                    this.limbs[i] += b.limbs[i];
                }

                this.numAdds = Math.max(this.numAdds, b.numAdds) + 1;
                return this;
            } else {
                throw new ArithmeticException("Not a valid summand");
            }
        }

        public IntegerPolynomial.MutableElement setDifference(IntegerModuloP genB) {
            IntegerPolynomial.Element b = (IntegerPolynomial.Element)genB;
            if (this.isSummand() && b.isSummand()) {
                for(int i = 0; i < this.limbs.length; ++i) {
                    this.limbs[i] -= b.limbs[i];
                }

                this.numAdds = Math.max(this.numAdds, b.numAdds) + 1;
                return this;
            } else {
                throw new ArithmeticException("Not a valid summand");
            }
        }

        public IntegerPolynomial.MutableElement setSquare() {
            IntegerPolynomial.this.square(this.limbs, this.limbs);
            this.numAdds = 0;
            return this;
        }

        public IntegerPolynomial.MutableElement setAdditiveInverse() {
            for(int i = 0; i < this.limbs.length; ++i) {
                this.limbs[i] = -this.limbs[i];
            }

            return this;
        }

        public IntegerPolynomial.MutableElement setReduced() {
            IntegerPolynomial.this.reduce(this.limbs);
            this.numAdds = 0;
            return this;
        }
    }

    private abstract class Element implements IntegerModuloP {
        protected long[] limbs;
        protected int numAdds;

        public Element(BigInteger v) {
            this.limbs = new long[IntegerPolynomial.this.numLimbs];
            this.setValue(v);
        }

        public Element(boolean v) {
            this.limbs = new long[IntegerPolynomial.this.numLimbs];
            this.limbs[0] = v ? 1L : 0L;
            this.numAdds = 0;
        }

        private Element(long[] limbs, int numAdds) {
            this.limbs = limbs;
            this.numAdds = numAdds;
        }

        private void setValue(BigInteger v) {
            IntegerPolynomial.this.setLimbsValue(v, this.limbs);
            this.numAdds = 0;
        }

        public IntegerFieldModuloP getField() {
            return IntegerPolynomial.this;
        }

        public BigInteger asBigInteger() {
            return IntegerPolynomial.this.evaluate(this.limbs);
        }

        public IntegerPolynomial.MutableElement mutable() {
            return IntegerPolynomial.this.new MutableElement((long[])this.limbs.clone(), this.numAdds);
        }

        protected boolean isSummand() {
            return this.numAdds < IntegerPolynomial.this.maxAdds;
        }

        public IntegerPolynomial.ImmutableElement add(IntegerModuloP genB) {
            IntegerPolynomial.Element b = (IntegerPolynomial.Element)genB;
            if (this.isSummand() && b.isSummand()) {
                long[] newLimbs = new long[this.limbs.length];

                int newNumAdds;
                for(newNumAdds = 0; newNumAdds < this.limbs.length; ++newNumAdds) {
                    newLimbs[newNumAdds] = this.limbs[newNumAdds] + b.limbs[newNumAdds];
                }

                newNumAdds = Math.max(this.numAdds, b.numAdds) + 1;
                return IntegerPolynomial.this.new ImmutableElement(newLimbs, newNumAdds);
            } else {
                throw new ArithmeticException("Not a valid summand");
            }
        }

        public IntegerPolynomial.ImmutableElement additiveInverse() {
            long[] newLimbs = new long[this.limbs.length];

            for(int i = 0; i < this.limbs.length; ++i) {
                newLimbs[i] = -this.limbs[i];
            }

            IntegerPolynomial.ImmutableElement result = IntegerPolynomial.this.new ImmutableElement(newLimbs, this.numAdds);
            return result;
        }

        protected long[] cloneLow(long[] limbs) {
            long[] newLimbs = new long[IntegerPolynomial.this.numLimbs];
            this.copyLow(limbs, newLimbs);
            return newLimbs;
        }

        protected void copyLow(long[] limbs, long[] out) {
            System.arraycopy(limbs, 0, out, 0, out.length);
        }

        public IntegerPolynomial.ImmutableElement multiply(IntegerModuloP genB) {
            IntegerPolynomial.Element b = (IntegerPolynomial.Element)genB;
            long[] newLimbs = new long[this.limbs.length];
            IntegerPolynomial.this.mult(this.limbs, b.limbs, newLimbs);
            return IntegerPolynomial.this.new ImmutableElement(newLimbs, 0);
        }

        public IntegerPolynomial.ImmutableElement square() {
            long[] newLimbs = new long[this.limbs.length];
            IntegerPolynomial.this.square(this.limbs, newLimbs);
            return IntegerPolynomial.this.new ImmutableElement(newLimbs, 0);
        }

        public void addModPowerTwo(IntegerModuloP arg, byte[] result) {
            IntegerPolynomial.Element other = (IntegerPolynomial.Element)arg;
            if (this.isSummand() && other.isSummand()) {
                IntegerPolynomial.this.addLimbsModPowerTwo(this.limbs, other.limbs, result);
            } else {
                throw new ArithmeticException("Not a valid summand");
            }
        }

        public void asByteArray(byte[] result) {
            if (!this.isSummand()) {
                throw new ArithmeticException("Not a valid summand");
            } else {
                IntegerPolynomial.this.limbsToByteArray(this.limbs, result);
            }
        }
    }
}
