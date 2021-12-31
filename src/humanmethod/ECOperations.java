package humanmethod;

import java.math.BigInteger;
import java.security.ProviderException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;
import java.util.Map;
import java.util.Optional;

public class ECOperations {
    static final Map<BigInteger, IntegerFieldModuloP> fields;
    static final Map<BigInteger, IntegerFieldModuloP> orderFields;
    final ImmutableIntegerModuloP b;
    final SmallValue one;
    final SmallValue two;
    final SmallValue three;
    final SmallValue four;
    final ProjectivePoint.Immutable neutral;
    private final IntegerFieldModuloP orderField;

    public static Optional<ECOperations> forParameters(ECParameterSpec params) {
        EllipticCurve curve = params.getCurve();
        if (!(curve.getField() instanceof ECFieldFp)) {
            return Optional.empty();
        } else {
            ECFieldFp primeField = (ECFieldFp)curve.getField();
            BigInteger three = BigInteger.valueOf(3L);
            if (!primeField.getP().subtract(curve.getA()).equals(three)) {
                return Optional.empty();
            } else {
                IntegerFieldModuloP field = (IntegerFieldModuloP)fields.get(primeField.getP());
                if (field == null) {
                    return Optional.empty();
                } else {
                    IntegerFieldModuloP orderField = (IntegerFieldModuloP)orderFields.get(params.getOrder());
                    if (orderField == null) {
                        return Optional.empty();
                    } else {
                        ImmutableIntegerModuloP b = field.getElement(curve.getB());
                        ECOperations ecOps = new ECOperations(b, orderField);
                        return Optional.of(ecOps);
                    }
                }
            }
        }
    }

    public ECOperations(IntegerModuloP b, IntegerFieldModuloP orderField) {
        this.b = b.fixed();
        this.orderField = orderField;
        this.one = b.getField().getSmallValue(1);
        this.two = b.getField().getSmallValue(2);
        this.three = b.getField().getSmallValue(3);
        this.four = b.getField().getSmallValue(4);
        IntegerFieldModuloP field = b.getField();
        this.neutral = new ProjectivePoint.Immutable(field.get0(), field.get1(), field.get0());
    }

    public IntegerFieldModuloP getField() {
        return this.b.getField();
    }

    public IntegerFieldModuloP getOrderField() {
        return this.orderField;
    }

    protected ProjectivePoint.Immutable getNeutral() {
        return this.neutral;
    }

    public boolean isNeutral(Point p) {
        ProjectivePoint<?> pp = (ProjectivePoint)p;
        IntegerModuloP z = pp.getZ();
        IntegerFieldModuloP field = z.getField();
        int byteLength = (field.getSize().bitLength() + 7) / 8;
        byte[] zBytes = z.asByteArray(byteLength);
        return allZero(zBytes);
    }

    byte[] seedToScalar(byte[] seedBytes) throws ECOperations.IntermediateValueException {
        int seedBits = this.orderField.getSize().bitLength() + 64;
        if (seedBytes.length * 8 < seedBits) {
            throw new ProviderException("Incorrect seed length: " + seedBytes.length * 8 + " < " + seedBits);
        } else {
            int lastByteBits = seedBits % 8;
            int seedLength;
            if (lastByteBits != 0) {
                seedLength = seedBits / 8;
                byte mask = (byte)(255 >>> 8 - lastByteBits);
                seedBytes[seedLength] &= mask;
            }

            seedLength = (seedBits + 7) / 8;
            IntegerModuloP scalarElem = this.orderField.getElement(seedBytes, 0, seedLength, (byte)0);
            int scalarLength = (this.orderField.getSize().bitLength() + 7) / 8;
            byte[] scalarArr = new byte[scalarLength];
            scalarElem.asByteArray(scalarArr);
            if (allZero(scalarArr)) {
                throw new ECOperations.IntermediateValueException();
            } else {
                return scalarArr;
            }
        }
    }

    public static boolean allZero(byte[] arr) {
        byte acc = 0;

        for(int i = 0; i < arr.length; ++i) {
            acc |= arr[i];
        }

        return acc == 0;
    }

    private void lookup4(ProjectivePoint.Immutable[] arr, int index, ProjectivePoint.Mutable result, IntegerModuloP zero) {
        for(int i = 0; i < 16; ++i) {
            int xor = index ^ i;
            int bit3 = (xor & 8) >>> 3;
            int bit2 = (xor & 4) >>> 2;
            int bit1 = (xor & 2) >>> 1;
            int bit0 = xor & 1;
            int inverse = bit0 | bit1 | bit2 | bit3;
            int set = 1 - inverse;
            ProjectivePoint.Immutable pi = arr[i];
            result.conditionalSet(pi, set);
        }

    }

    private void double4(ProjectivePoint.Mutable p, MutableIntegerModuloP t0, MutableIntegerModuloP t1, MutableIntegerModuloP t2, MutableIntegerModuloP t3, MutableIntegerModuloP t4) {
        for(int i = 0; i < 4; ++i) {
            this.setDouble(p, t0, t1, t2, t3, t4);
        }

    }

    public MutablePoint multiply(AffinePoint affineP, byte[] s) {
        IntegerFieldModuloP field = affineP.getX().getField();
        ImmutableIntegerModuloP zero = field.get0();
        MutableIntegerModuloP t0 = zero.mutable();
        MutableIntegerModuloP t1 = zero.mutable();
        MutableIntegerModuloP t2 = zero.mutable();
        MutableIntegerModuloP t3 = zero.mutable();
        MutableIntegerModuloP t4 = zero.mutable();
        ProjectivePoint.Mutable result = new ProjectivePoint.Mutable(field);
        ((MutableIntegerModuloP)result.getY()).setValue(field.get1().mutable());
        ProjectivePoint.Immutable[] pointMultiples = new ProjectivePoint.Immutable[16];
        pointMultiples[0] = result.fixed();
        ProjectivePoint.Mutable ps = new ProjectivePoint.Mutable(field);
        ps.setValue(affineP);
        pointMultiples[1] = ps.fixed();

        for(int i = 2; i < 16; ++i) {
            this.setSum(ps, affineP, t0, t1, t2, t3, t4);
            pointMultiples[i] = ps.fixed();
        }

        ProjectivePoint.Mutable lookupResult = ps.mutable();
        /**
        System.out.println("t0: "+t0.asBigInteger().toString());
        System.out.println("t1: "+t1.asBigInteger().toString());
        System.out.println("t2: "+t2.asBigInteger().toString());
        System.out.println("t3: "+t3.asBigInteger().toString());
        System.out.println("t4: "+t4.asBigInteger().toString());
        System.out.println("result.x: "+result.x.asBigInteger().toString());
        System.out.println("result.y: "+result.y.asBigInteger().toString());
        System.out.println("result.z: "+result.z.asBigInteger().toString());
        System.out.println("result.asAffine() public: "+ result.asAffine().getX().asBigInteger()+","+ result.asAffine().getY().asBigInteger());**/
        //System.out.println("-------NEXT------");
        //int i=31;
        for(int i = s.length - 1; i >= 0; --i) {
            this.double4(result, t0, t1, t2, t3, t4);
            int high = (255 & s[i]) >>> 4; //In my opinion max value here is 15 and minimum is 0
            this.lookup4(pointMultiples, high, lookupResult, zero);
            this.setSum(result, lookupResult, t0, t1, t2, t3, t4);
            this.double4(result, t0, t1, t2, t3, t4);
            int low = 15 & s[i]; //In my opinion max value here is 15 and minimum is 0
            this.lookup4(pointMultiples, low, lookupResult, zero);
            this.setSum(result, lookupResult, t0, t1, t2, t3, t4);
        }
        //System.out.println("t0: "+t0.asBigInteger().toString());
        //System.out.println("t1: "+t1.asBigInteger().toString());
        //System.out.println("t2: "+t2.asBigInteger().toString());
        //System.out.println("t3: "+t3.asBigInteger().toString());
        //System.out.println("t4: "+t4.asBigInteger().toString());
        //System.out.println("result.x: "+result.x.asBigInteger().toString());
        //System.out.println("result.y: "+result.y.asBigInteger().toString());
        //System.out.println("result.z: "+result.z.asBigInteger().toString());
        System.out.println(result.x.asBigInteger().toString()+" "+result.y.asBigInteger().toString()+" "+result.z.asBigInteger().toString());
        return result;
    }

    private void setDouble(ProjectivePoint.Mutable p, MutableIntegerModuloP t0, MutableIntegerModuloP t1, MutableIntegerModuloP t2, MutableIntegerModuloP t3, MutableIntegerModuloP t4) {
        t0.setValue(p.getX()).setSquare();
        t1.setValue(p.getY()).setSquare();
        t2.setValue(p.getZ()).setSquare();
        t3.setValue(p.getX()).setProduct(p.getY());
        t4.setValue(p.getY()).setProduct(p.getZ());
        t3.setSum(t3);
        ((MutableIntegerModuloP)p.getZ()).setProduct(p.getX());
        ((MutableIntegerModuloP)p.getZ()).setProduct(this.two);
        ((MutableIntegerModuloP)p.getY()).setValue(t2).setProduct(this.b);
        ((MutableIntegerModuloP)p.getY()).setDifference(p.getZ());
        ((MutableIntegerModuloP)p.getX()).setValue(p.getY()).setProduct(this.two);
        ((MutableIntegerModuloP)p.getY()).setSum(p.getX());
        ((MutableIntegerModuloP)p.getY()).setReduced();
        ((MutableIntegerModuloP)p.getX()).setValue(t1).setDifference(p.getY());
        ((MutableIntegerModuloP)p.getY()).setSum(t1);
        ((MutableIntegerModuloP)p.getY()).setProduct(p.getX());
        ((MutableIntegerModuloP)p.getX()).setProduct(t3);
        t3.setValue(t2).setProduct(this.two);
        t2.setSum(t3);
        ((MutableIntegerModuloP)p.getZ()).setProduct(this.b);
        t2.setReduced();
        ((MutableIntegerModuloP)p.getZ()).setDifference(t2);
        ((MutableIntegerModuloP)p.getZ()).setDifference(t0);
        t3.setValue(p.getZ()).setProduct(this.two);
        ((MutableIntegerModuloP)p.getZ()).setReduced();
        ((MutableIntegerModuloP)p.getZ()).setSum(t3);
        t0.setProduct(this.three);
        t0.setDifference(t2);
        t0.setProduct(p.getZ());
        ((MutableIntegerModuloP)p.getY()).setSum(t0);
        t4.setSum(t4);
        ((MutableIntegerModuloP)p.getZ()).setProduct(t4);
        ((MutableIntegerModuloP)p.getX()).setDifference(p.getZ());
        ((MutableIntegerModuloP)p.getZ()).setValue(t4).setProduct(t1);
        ((MutableIntegerModuloP)p.getZ()).setProduct(this.four);
    }

    public void setSum(MutablePoint p, AffinePoint p2) {
        IntegerModuloP zero = p.getField().get0();
        MutableIntegerModuloP t0 = zero.mutable();
        MutableIntegerModuloP t1 = zero.mutable();
        MutableIntegerModuloP t2 = zero.mutable();
        MutableIntegerModuloP t3 = zero.mutable();
        MutableIntegerModuloP t4 = zero.mutable();
        this.setSum((ProjectivePoint.Mutable)p, p2, t0, t1, t2, t3, t4);
    }

    private void setSum(ProjectivePoint.Mutable p, AffinePoint p2, MutableIntegerModuloP t0, MutableIntegerModuloP t1, MutableIntegerModuloP t2, MutableIntegerModuloP t3, MutableIntegerModuloP t4) {
        t0.setValue(p.getX()).setProduct(p2.getX());
        t1.setValue(p.getY()).setProduct(p2.getY());
        t3.setValue(p2.getX()).setSum(p2.getY());
        t4.setValue(p.getX()).setSum(p.getY());
        ((MutableIntegerModuloP)p.getX()).setReduced();
        t3.setProduct(t4);
        t4.setValue(t0).setSum(t1);
        t3.setDifference(t4);
        t4.setValue(p2.getY()).setProduct(p.getZ());
        t4.setSum(p.getY());
        ((MutableIntegerModuloP)p.getY()).setValue(p2.getX()).setProduct(p.getZ());
        ((MutableIntegerModuloP)p.getY()).setSum(p.getX());
        t2.setValue(p.getZ());
        ((MutableIntegerModuloP)p.getZ()).setProduct(this.b);
        ((MutableIntegerModuloP)p.getX()).setValue(p.getY()).setDifference(p.getZ());
        ((MutableIntegerModuloP)p.getX()).setReduced();
        ((MutableIntegerModuloP)p.getZ()).setValue(p.getX()).setProduct(this.two);
        ((MutableIntegerModuloP)p.getX()).setSum(p.getZ());
        ((MutableIntegerModuloP)p.getZ()).setValue(t1).setDifference(p.getX());
        ((MutableIntegerModuloP)p.getX()).setSum(t1);
        ((MutableIntegerModuloP)p.getY()).setProduct(this.b);
        t1.setValue(t2).setProduct(this.two);
        t2.setSum(t1);
        t2.setReduced();
        ((MutableIntegerModuloP)p.getY()).setDifference(t2);
        ((MutableIntegerModuloP)p.getY()).setDifference(t0);
        ((MutableIntegerModuloP)p.getY()).setReduced();
        t1.setValue(p.getY()).setProduct(this.two);
        ((MutableIntegerModuloP)p.getY()).setSum(t1);
        t1.setValue(t0).setProduct(this.two);
        t0.setSum(t1);
        t0.setDifference(t2);
        t1.setValue(t4).setProduct(p.getY());
        t2.setValue(t0).setProduct(p.getY());
        ((MutableIntegerModuloP)p.getY()).setValue(p.getX()).setProduct(p.getZ());
        ((MutableIntegerModuloP)p.getY()).setSum(t2);
        ((MutableIntegerModuloP)p.getX()).setProduct(t3);
        ((MutableIntegerModuloP)p.getX()).setDifference(t1);
        ((MutableIntegerModuloP)p.getZ()).setProduct(t4);
        t1.setValue(t3).setProduct(t0);
        ((MutableIntegerModuloP)p.getZ()).setSum(t1);
    }

    private void setSum(ProjectivePoint.Mutable p, ProjectivePoint.Mutable p2, MutableIntegerModuloP t0, MutableIntegerModuloP t1, MutableIntegerModuloP t2, MutableIntegerModuloP t3, MutableIntegerModuloP t4) {
        t0.setValue(p.getX()).setProduct(p2.getX());
        t1.setValue(p.getY()).setProduct(p2.getY());
        t2.setValue(p.getZ()).setProduct(p2.getZ());
        t3.setValue(p.getX()).setSum(p.getY());
        t4.setValue(p2.getX()).setSum(p2.getY());
        t3.setProduct(t4);
        t4.setValue(t0).setSum(t1);
        t3.setDifference(t4);
        t4.setValue(p.getY()).setSum(p.getZ());
        ((MutableIntegerModuloP)p.getY()).setValue(p2.getY()).setSum(p2.getZ());
        t4.setProduct(p.getY());
        ((MutableIntegerModuloP)p.getY()).setValue(t1).setSum(t2);
        t4.setDifference(p.getY());
        ((MutableIntegerModuloP)p.getX()).setSum(p.getZ());
        ((MutableIntegerModuloP)p.getY()).setValue(p2.getX()).setSum(p2.getZ());
        ((MutableIntegerModuloP)p.getX()).setProduct(p.getY());
        ((MutableIntegerModuloP)p.getY()).setValue(t0).setSum(t2);
        ((MutableIntegerModuloP)p.getY()).setAdditiveInverse().setSum(p.getX());
        ((MutableIntegerModuloP)p.getY()).setReduced();
        ((MutableIntegerModuloP)p.getZ()).setValue(t2).setProduct(this.b);
        ((MutableIntegerModuloP)p.getX()).setValue(p.getY()).setDifference(p.getZ());
        ((MutableIntegerModuloP)p.getZ()).setValue(p.getX()).setProduct(this.two);
        ((MutableIntegerModuloP)p.getX()).setSum(p.getZ());
        ((MutableIntegerModuloP)p.getX()).setReduced();
        ((MutableIntegerModuloP)p.getZ()).setValue(t1).setDifference(p.getX());
        ((MutableIntegerModuloP)p.getX()).setSum(t1);
        ((MutableIntegerModuloP)p.getY()).setProduct(this.b);
        t1.setValue(t2).setSum(t2);
        t2.setSum(t1);
        t2.setReduced();
        ((MutableIntegerModuloP)p.getY()).setDifference(t2);
        ((MutableIntegerModuloP)p.getY()).setDifference(t0);
        ((MutableIntegerModuloP)p.getY()).setReduced();
        t1.setValue(p.getY()).setSum(p.getY());
        ((MutableIntegerModuloP)p.getY()).setSum(t1);
        t1.setValue(t0).setProduct(this.two);
        t0.setSum(t1);
        t0.setDifference(t2);
        t1.setValue(t4).setProduct(p.getY());
        t2.setValue(t0).setProduct(p.getY());
        ((MutableIntegerModuloP)p.getY()).setValue(p.getX()).setProduct(p.getZ());
        ((MutableIntegerModuloP)p.getY()).setSum(t2);
        ((MutableIntegerModuloP)p.getX()).setProduct(t3);
        ((MutableIntegerModuloP)p.getX()).setDifference(t1);
        ((MutableIntegerModuloP)p.getZ()).setProduct(t4);
        t1.setValue(t3).setProduct(t0);
        ((MutableIntegerModuloP)p.getZ()).setSum(t1);
    }

    static {
        fields = Map.of(IntegerPolynomialP256.MODULUS, new IntegerPolynomialP256(), IntegerPolynomialP384.MODULUS, new IntegerPolynomialP384(), IntegerPolynomialP521.MODULUS, new IntegerPolynomialP521());
        orderFields = Map.of(P256OrderField.MODULUS, new P256OrderField(), P384OrderField.MODULUS, new P384OrderField(), P521OrderField.MODULUS, new P521OrderField());
    }

    static class IntermediateValueException extends Exception {
        private static final long serialVersionUID = 1L;

        IntermediateValueException() {
        }
    }
}
