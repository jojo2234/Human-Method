package humanmethod;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SignatureException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public final class ECUtil {
    public static ECPoint decodePoint(byte[] data, EllipticCurve curve) throws IOException {
        if (data.length != 0 && data[0] == 4) {
            int n = (data.length - 1) / 2;
            if (n != curve.getField().getFieldSize() + 7 >> 3) {
                throw new IOException("Point does not match field size");
            } else {
                byte[] xb = Arrays.copyOfRange(data, 1, 1 + n);
                byte[] yb = Arrays.copyOfRange(data, n + 1, n + 1 + n);
                return new ECPoint(new BigInteger(1, xb), new BigInteger(1, yb));
            }
        } else {
            throw new IOException("Only uncompressed point format supported");
        }
    }

    public static byte[] encodePoint(ECPoint point, EllipticCurve curve) {
        int n = curve.getField().getFieldSize() + 7 >> 3;
        byte[] xb = trimZeroes(point.getAffineX().toByteArray());
        byte[] yb = trimZeroes(point.getAffineY().toByteArray());
        if (xb.length <= n && yb.length <= n) {
            byte[] b = new byte[1 + (n << 1)];
            b[0] = 4;
            System.arraycopy(xb, 0, b, n - xb.length + 1, xb.length);
            System.arraycopy(yb, 0, b, b.length - yb.length, yb.length);
            return b;
        } else {
            throw new RuntimeException("Point coordinates do not match field size");
        }
    }

    public static byte[] trimZeroes(byte[] b) {
        int i;
        for(i = 0; i < b.length - 1 && b[i] == 0; ++i) {
        }

        return i == 0 ? b : Arrays.copyOfRange(b, i, b.length);
    }

    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance("EC", "SunEC");
        } catch (NoSuchProviderException | NoSuchAlgorithmException var1) {
            throw new RuntimeException(var1);
        }
    }

    public static ECPublicKey decodeX509ECPublicKey(byte[] encoded) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
        return (ECPublicKey)keyFactory.generatePublic(keySpec);
    }

    public static byte[] x509EncodeECPublicKey(ECPoint w, ECParameterSpec params) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        ECPublicKeySpec keySpec = new ECPublicKeySpec(w, params);
        X509Key key = (X509Key)keyFactory.generatePublic(keySpec);
        return key.getEncoded();
    }

    public static ECPrivateKey decodePKCS8ECPrivateKey(byte[] encoded) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
        return (ECPrivateKey)keyFactory.generatePrivate(keySpec);
    }

    public static ECPrivateKey generateECPrivateKey(BigInteger s, ECParameterSpec params) throws InvalidKeySpecException {
        KeyFactory keyFactory = getKeyFactory();
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(s, params);
        return (ECPrivateKey)keyFactory.generatePrivate(keySpec);
    }

    public static AlgorithmParameters getECParameters(Provider p) {
        try {
            return p != null ? AlgorithmParameters.getInstance("EC", p) : AlgorithmParameters.getInstance("EC");
        } catch (NoSuchAlgorithmException var2) {
            throw new RuntimeException(var2);
        }
    }

    public static byte[] encodeECParameterSpec(Provider p, ECParameterSpec spec) {
        AlgorithmParameters parameters = getECParameters(p);

        try {
            parameters.init(spec);
        } catch (InvalidParameterSpecException var5) {
            throw new RuntimeException("Not a known named curve: " + spec);
        }

        try {
            return parameters.getEncoded();
        } catch (IOException var4) {
            throw new RuntimeException(var4);
        }
    }

    public static ECParameterSpec getECParameterSpec(Provider p, ECParameterSpec spec) {
        AlgorithmParameters parameters = getECParameters(p);

        try {
            parameters.init(spec);
            return (ECParameterSpec)parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException var4) {
            return null;
        }
    }

    public static ECParameterSpec getECParameterSpec(Provider p, byte[] params) throws IOException {
        AlgorithmParameters parameters = getECParameters(p);
        parameters.init(params);

        try {
            return (ECParameterSpec)parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException var4) {
            return null;
        }
    }

    public static ECParameterSpec getECParameterSpec(Provider p, String name) {
        AlgorithmParameters parameters = getECParameters(p);

        try {
            parameters.init(new ECGenParameterSpec(name));
            return (ECParameterSpec)parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException var4) {
            return null;
        }
    }

    public static ECParameterSpec getECParameterSpec(Provider p, int keySize) {
        AlgorithmParameters parameters = getECParameters(p);

        try {
            parameters.init(new ECKeySizeParameterSpec(keySize));
            return (ECParameterSpec)parameters.getParameterSpec(ECParameterSpec.class);
        } catch (InvalidParameterSpecException var4) {
            return null;
        }
    }

    public static String getCurveName(Provider p, ECParameterSpec spec) {
        AlgorithmParameters parameters = getECParameters(p);

        ECGenParameterSpec nameSpec;
        try {
            parameters.init(spec);
            nameSpec = (ECGenParameterSpec)parameters.getParameterSpec(ECGenParameterSpec.class);
        } catch (InvalidParameterSpecException var5) {
            return null;
        }

        return nameSpec == null ? null : nameSpec.getName();
    }

    public static boolean equals(ECParameterSpec spec1, ECParameterSpec spec2) {
        if (spec1 == spec2) {
            return true;
        } else if (spec1 != null && spec2 != null) {
            return spec1.getCofactor() == spec2.getCofactor() && spec1.getOrder().equals(spec2.getOrder()) && spec1.getCurve().equals(spec2.getCurve()) && spec1.getGenerator().equals(spec2.getGenerator());
        } else {
            return false;
        }
    }

    public static byte[] encodeSignature(byte[] signature) throws SignatureException {
        try {
            int n = signature.length >> 1;
            byte[] bytes = new byte[n];
            System.arraycopy(signature, 0, bytes, 0, n);
            BigInteger r = new BigInteger(1, bytes);
            System.arraycopy(signature, n, bytes, 0, n);
            BigInteger s = new BigInteger(1, bytes);
            DerOutputStream out = new DerOutputStream(signature.length + 10);
            out.putInteger(r);
            out.putInteger(s);
            DerValue result = new DerValue((byte)48, out.toByteArray());
            return result.toByteArray();
        } catch (Exception var7) {
            throw new SignatureException("Could not encode signature", var7);
        }
    }

    public static byte[] decodeSignature(byte[] sig) throws SignatureException {
        try {
            DerInputStream in = new DerInputStream(sig, 0, sig.length, false);
            DerValue[] values = in.getSequence(2);
            if (values.length == 2 && in.available() == 0) {
                BigInteger r = values[0].getPositiveBigInteger();
                BigInteger s = values[1].getPositiveBigInteger();
                byte[] rBytes = trimZeroes(r.toByteArray());
                byte[] sBytes = trimZeroes(s.toByteArray());
                int k = Math.max(rBytes.length, sBytes.length);
                byte[] result = new byte[k << 1];
                System.arraycopy(rBytes, 0, result, k - rBytes.length, rBytes.length);
                System.arraycopy(sBytes, 0, result, result.length - sBytes.length, sBytes.length);
                return result;
            } else {
                throw new IOException("Invalid encoding for signature");
            }
        } catch (Exception var9) {
            throw new SignatureException("Invalid encoding for signature", var9);
        }
    }

    private ECUtil() {
    }
}
