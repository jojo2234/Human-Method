package humanmethod;

import humanmethod.ECOperations.IntermediateValueException;
import java.security.ProviderException;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Optional;

public class ECDSAOperations {
    private final ECOperations ecOps;
    private final AffinePoint basePoint;

    public ECDSAOperations(ECOperations ecOps, ECPoint basePoint) {
        this.ecOps = ecOps;
        this.basePoint = toAffinePoint(basePoint, ecOps.getField());
    }

    public ECOperations getEcOperations() {
        return this.ecOps;
    }

    public AffinePoint basePointMultiply(byte[] scalar) {
        return this.ecOps.multiply(this.basePoint, scalar).asAffine();
    }

    public static AffinePoint toAffinePoint(ECPoint point, IntegerFieldModuloP field) {
        ImmutableIntegerModuloP affineX = field.getElement(point.getAffineX());
        ImmutableIntegerModuloP affineY = field.getElement(point.getAffineY());
        return new AffinePoint(affineX, affineY);
    }

    public static Optional<ECDSAOperations> forParameters(ECParameterSpec ecParams) {
        Optional<ECOperations> curveOps = ECOperations.forParameters(ecParams);
        return curveOps.map((ops) -> {
            return new ECDSAOperations(ops, ecParams.getGenerator());
        });
    }

    public byte[] signDigest(byte[] privateKey, byte[] digest, ECDSAOperations.Seed seed) throws IntermediateValueException {
        byte[] nonceArr = this.ecOps.seedToScalar(seed.getSeedValue());
        ECDSAOperations.Nonce nonce = new ECDSAOperations.Nonce(nonceArr);
        return this.signDigest(privateKey, digest, nonce);
    }

    public byte[] signDigest(byte[] privateKey, byte[] digest, ECDSAOperations.Nonce nonce) throws IntermediateValueException {
        IntegerFieldModuloP orderField = this.ecOps.getOrderField();
        int orderBits = orderField.getSize().bitLength();
        if (orderBits % 8 != 0 && orderBits < digest.length * 8) {
            throw new ProviderException("Invalid digest length");
        } else {
            byte[] k = nonce.getNonceValue();
            int length = (orderField.getSize().bitLength() + 7) / 8;
            if (k.length != length) {
                throw new ProviderException("Incorrect nonce length");
            } else {
                MutablePoint R = this.ecOps.multiply(this.basePoint, k);
                IntegerModuloP r = R.asAffine().getX();
                byte[] temp = new byte[length];
                r.asByteArray(temp);
                r = orderField.getElement(temp);
                r.asByteArray(temp);
                byte[] result = new byte[2 * length];
                ArrayUtil.reverse(temp);
                System.arraycopy(temp, 0, result, 0, length);
                if (ECOperations.allZero(temp)) {
                    throw new IntermediateValueException();
                } else {
                    IntegerModuloP dU = orderField.getElement(privateKey);
                    int lengthE = Math.min(length, digest.length);
                    byte[] E = new byte[lengthE];
                    System.arraycopy(digest, 0, E, 0, lengthE);
                    ArrayUtil.reverse(E);
                    IntegerModuloP e = orderField.getElement(E);
                    IntegerModuloP kElem = orderField.getElement(k);
                    IntegerModuloP kInv = kElem.multiplicativeInverse();
                    MutableIntegerModuloP s = r.mutable();
                    s.setProduct(dU).setSum(e).setProduct(kInv);
                    s.asByteArray(temp);
                    ArrayUtil.reverse(temp);
                    System.arraycopy(temp, 0, result, length, length);
                    if (ECOperations.allZero(temp)) {
                        throw new IntermediateValueException();
                    } else {
                        return result;
                    }
                }
            }
        }
    }

    public static class Nonce {
        private final byte[] nonceValue;

        public Nonce(byte[] nonceValue) {
            this.nonceValue = nonceValue;
        }

        public byte[] getNonceValue() {
            return this.nonceValue;
        }
    }

    public static class Seed {
        private final byte[] seedValue;

        public Seed(byte[] seedValue) {
            this.seedValue = seedValue;
        }

        public byte[] getSeedValue() {
            return this.seedValue;
        }
    }
}