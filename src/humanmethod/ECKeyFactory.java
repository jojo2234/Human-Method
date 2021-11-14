package humanmethod;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyFactorySpi;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public final class ECKeyFactory extends KeyFactorySpi {
    private static KeyFactory instance;

    private static KeyFactory getInstance() {
        if (instance == null) {
            try {
                instance = KeyFactory.getInstance("EC", "SunEC");
            } catch (NoSuchProviderException var1) {
                throw new RuntimeException(var1);
            } catch (NoSuchAlgorithmException var2) {
                throw new RuntimeException(var2);
            }
        }

        return instance;
    }

    public ECKeyFactory() {
    }

    public static ECKey toECKey(Key key) throws InvalidKeyException {
        if (key instanceof ECKey) {
            ECKey ecKey = (ECKey)key;
            checkKey(ecKey);
            return ecKey;
        } else {
            return (ECKey)getInstance().translateKey(key);
        }
    }

    private static void checkKey(ECKey key) throws InvalidKeyException {
        if (key instanceof ECPublicKey) {
            if (key instanceof ECPublicKeyImpl) {
                return;
            }
        } else {
            if (!(key instanceof ECPrivateKey)) {
                throw new InvalidKeyException("Neither a public nor a private key");
            }

            if (key instanceof ECPrivateKeyImpl) {
                return;
            }
        }

        String keyAlg = ((Key)key).getAlgorithm();
        if (!keyAlg.equals("EC")) {
            throw new InvalidKeyException("Not an EC key: " + keyAlg);
        }
    }

    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("Key must not be null");
        } else {
            String keyAlg = key.getAlgorithm();
            if (!keyAlg.equals("EC")) {
                throw new InvalidKeyException("Not an EC key: " + keyAlg);
            } else if (key instanceof PublicKey) {
                return this.implTranslatePublicKey((PublicKey)key);
            } else if (key instanceof PrivateKey) {
                return this.implTranslatePrivateKey((PrivateKey)key);
            } else {
                throw new InvalidKeyException("Neither a public nor a private key");
            }
        }
    }

    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            return this.implGeneratePublic(keySpec);
        } catch (InvalidKeySpecException var3) {
            throw var3;
        } catch (GeneralSecurityException var4) {
            throw new InvalidKeySpecException(var4);
        }
    }

    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        try {
            return this.implGeneratePrivate(keySpec);
        } catch (InvalidKeySpecException var3) {
            throw var3;
        } catch (GeneralSecurityException var4) {
            throw new InvalidKeySpecException(var4);
        }
    }

    private PublicKey implTranslatePublicKey(PublicKey key) throws InvalidKeyException {
        if (key instanceof ECPublicKey) {
            if (key instanceof ECPublicKeyImpl) {
                return key;
            } else {
                ECPublicKey ecKey = (ECPublicKey)key;
                return new ECPublicKeyImpl(ecKey.getW(), ecKey.getParams());
            }
        } else if ("X.509".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            return new ECPublicKeyImpl(encoded);
        } else {
            throw new InvalidKeyException("Public keys must be instance of ECPublicKey or have X.509 encoding");
        }
    }

    private PrivateKey implTranslatePrivateKey(PrivateKey key) throws InvalidKeyException {
        if (key instanceof ECPrivateKey) {
            if (key instanceof ECPrivateKeyImpl) {
                return key;
            } else {
                ECPrivateKey ecKey = (ECPrivateKey)key;
                return new ECPrivateKeyImpl(ecKey.getS(), ecKey.getParams());
            }
        } else if ("PKCS#8".equals(key.getFormat())) {
            return new ECPrivateKeyImpl(key.getEncoded());
        } else {
            throw new InvalidKeyException("Private keys must be instance of ECPrivateKey or have PKCS#8 encoding");
        }
    }

    private PublicKey implGeneratePublic(KeySpec keySpec) throws GeneralSecurityException {
        if (keySpec instanceof X509EncodedKeySpec) {
            X509EncodedKeySpec x509Spec = (X509EncodedKeySpec)keySpec;
            return new ECPublicKeyImpl(x509Spec.getEncoded());
        } else if (keySpec instanceof ECPublicKeySpec) {
            ECPublicKeySpec ecSpec = (ECPublicKeySpec)keySpec;
            return new ECPublicKeyImpl(ecSpec.getW(), ecSpec.getParams());
        } else {
            throw new InvalidKeySpecException("Only ECPublicKeySpec and X509EncodedKeySpec supported for EC public keys");
        }
    }

    private PrivateKey implGeneratePrivate(KeySpec keySpec) throws GeneralSecurityException {
        if (keySpec instanceof PKCS8EncodedKeySpec) {
            PKCS8EncodedKeySpec pkcsSpec = (PKCS8EncodedKeySpec)keySpec;
            return new ECPrivateKeyImpl(pkcsSpec.getEncoded());
        } else if (keySpec instanceof ECPrivateKeySpec) {
            ECPrivateKeySpec ecSpec = (ECPrivateKeySpec)keySpec;
            return new ECPrivateKeyImpl(ecSpec.getS(), ecSpec.getParams());
        } else {
            throw new InvalidKeySpecException("Only ECPrivateKeySpec and PKCS8EncodedKeySpec supported for EC private keys");
        }
    }

    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        try {
            key = this.engineTranslateKey(key);
        } catch (InvalidKeyException var4) {
            throw new InvalidKeySpecException(var4);
        }

        if (key instanceof ECPublicKey) {
            ECPublicKey ecKey = (ECPublicKey)key;
            if (ECPublicKeySpec.class.isAssignableFrom(keySpec)) {
                return (T)(KeySpec)keySpec.cast(new ECPublicKeySpec(ecKey.getW(), ecKey.getParams()));
            } else if (X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T)(KeySpec)keySpec.cast(new X509EncodedKeySpec(key.getEncoded()));
            } else {
                throw new InvalidKeySpecException("KeySpec must be ECPublicKeySpec or X509EncodedKeySpec for EC public keys");
            }
        } else if (key instanceof ECPrivateKey) {
            if (PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
                return (T)(KeySpec)keySpec.cast(new PKCS8EncodedKeySpec(key.getEncoded()));
            } else if (ECPrivateKeySpec.class.isAssignableFrom(keySpec)) {
                ECPrivateKey ecKey = (ECPrivateKey)key;
                return (T)(KeySpec)keySpec.cast(new ECPrivateKeySpec(ecKey.getS(), ecKey.getParams()));
            } else {
                throw new InvalidKeySpecException("KeySpec must be ECPrivateKeySpec or PKCS8EncodedKeySpec for EC private keys");
            }
        } else {
            throw new InvalidKeySpecException("Neither public nor private key");
        }
    }
}
