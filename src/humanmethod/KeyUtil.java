package humanmethod;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.DSAKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;


public final class KeyUtil {
    public KeyUtil() {
    }

    public static final int getKeySize(Key key) {
        int size = -1;
        if (key instanceof Length) {
            try {
                Length ruler = (Length)key;
                size = ruler.length();
            } catch (UnsupportedOperationException var4) {
            }

            if (size >= 0) {
                return size;
            }
        }

        if (key instanceof SecretKey) {
            SecretKey sk = (SecretKey)key;
            String format = sk.getFormat();
            if ("RAW".equals(format) && sk.getEncoded() != null) {
                size = sk.getEncoded().length * 8;
            }
        } else if (key instanceof RSAKey) {
            RSAKey pubk = (RSAKey)key;
            size = pubk.getModulus().bitLength();
        } else if (key instanceof ECKey) {
            ECKey pubk = (ECKey)key;
            size = pubk.getParams().getOrder().bitLength();
        } else if (key instanceof DSAKey) {
            DSAKey pubk = (DSAKey)key;
            DSAParams params = pubk.getParams();
            size = params != null ? params.getP().bitLength() : -1;
        } else if (key instanceof DHKey) {
            DHKey pubk = (DHKey)key;
            size = pubk.getParams().getP().bitLength();
        }

        return size;
    }

    public static final int getKeySize(AlgorithmParameters parameters) {
        String algorithm = parameters.getAlgorithm();
        byte var3 = -1;
        switch(algorithm.hashCode()) {
        case -1976312388:
            if (algorithm.equals("DiffieHellman")) {
                var3 = 1;
            }
            break;
        case 2206:
            if (algorithm.equals("EC")) {
                var3 = 0;
            }
        }

        switch(var3) {
        case 0:
            try {
                ECKeySizeParameterSpec ps = (ECKeySizeParameterSpec)parameters.getParameterSpec(ECKeySizeParameterSpec.class);
                if (ps != null) {
                    return ps.getKeySize();
                }
            } catch (InvalidParameterSpecException var7) {
            }

            try {
                ECParameterSpec ps = (ECParameterSpec)parameters.getParameterSpec(ECParameterSpec.class);
                if (ps != null) {
                    return ps.getOrder().bitLength();
                }
            } catch (InvalidParameterSpecException var6) {
            }
            break;
        case 1:
            try {
                DHParameterSpec ps = (DHParameterSpec)parameters.getParameterSpec(DHParameterSpec.class);
                if (ps != null) {
                    return ps.getP().bitLength();
                }
            } catch (InvalidParameterSpecException var5) {
            }
        }

        return -1;
    }

    public static final void validate(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new NullPointerException("The key to be validated cannot be null");
        } else {
            if (key instanceof DHPublicKey) {
                validateDHPublicKey((DHPublicKey)key);
            }

        }
    }

    public static final void validate(KeySpec keySpec) throws InvalidKeyException {
        if (keySpec == null) {
            throw new NullPointerException("The key spec to be validated cannot be null");
        } else {
            if (keySpec instanceof DHPublicKeySpec) {
                validateDHPublicKey((DHPublicKeySpec)keySpec);
            }

        }
    }

    public static final boolean isOracleJCEProvider(String providerName) {
        return providerName != null && (providerName.equals("SunJCE") || providerName.equals("SunMSCAPI") || providerName.equals("OracleUcrypto") || providerName.startsWith("SunPKCS11"));
    }

    public static byte[] checkTlsPreMasterSecretKey(int clientVersion, int serverVersion, SecureRandom random, byte[] encoded, boolean isFailOver) {
        if (random == null) {
            random = JCAUtil.getSecureRandom();
        }

        byte[] replacer = new byte[48];
        random.nextBytes(replacer);
        if (!isFailOver && encoded != null) {
            if (encoded.length != 48) {
                return replacer;
            } else {
                int encodedVersion = (encoded[0] & 255) << 8 | encoded[1] & 255;
                if (clientVersion != encodedVersion && (clientVersion > 769 || serverVersion != encodedVersion)) {
                    encoded = replacer;
                }

                return encoded;
            }
        } else {
            return replacer;
        }
    }

    private static void validateDHPublicKey(DHPublicKey publicKey) throws InvalidKeyException {
        DHParameterSpec paramSpec = publicKey.getParams();
        BigInteger p = paramSpec.getP();
        BigInteger g = paramSpec.getG();
        BigInteger y = publicKey.getY();
        validateDHPublicKey(p, g, y);
    }

    private static void validateDHPublicKey(DHPublicKeySpec publicKeySpec) throws InvalidKeyException {
        validateDHPublicKey(publicKeySpec.getP(), publicKeySpec.getG(), publicKeySpec.getY());
    }

    private static void validateDHPublicKey(BigInteger p, BigInteger g, BigInteger y) throws InvalidKeyException {
        BigInteger leftOpen = BigInteger.ONE;
        BigInteger rightOpen = p.subtract(BigInteger.ONE);
        if (y.compareTo(leftOpen) <= 0) {
            throw new InvalidKeyException("Diffie-Hellman public key is too small");
        } else if (y.compareTo(rightOpen) >= 0) {
            throw new InvalidKeyException("Diffie-Hellman public key is too large");
        } else {
            BigInteger r = p.remainder(y);
            if (r.equals(BigInteger.ZERO)) {
                throw new InvalidKeyException("Invalid Diffie-Hellman parameters");
            }
        }
    }

    public static byte[] trimZeroes(byte[] b) {
        int i;
        for(i = 0; i < b.length - 1 && b[i] == 0; ++i) {
        }

        if (i == 0) {
            return b;
        } else {
            byte[] t = new byte[b.length - i];
            System.arraycopy(b, i, t, 0, t.length);
            return t;
        }
    }
}
