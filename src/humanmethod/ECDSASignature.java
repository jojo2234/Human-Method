package humanmethod;

import humanmethod.ECDSAOperations.Seed;
import humanmethod.ECOperations.IntermediateValueException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Optional;

abstract class ECDSASignature extends SignatureSpi {
    private final MessageDigest messageDigest;
    private SecureRandom random;
    private boolean needsReset;
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;
    private ECParameterSpec sigParams;
    private final boolean p1363Format;

    ECDSASignature() {
        this(false);
    }

    ECDSASignature(boolean p1363Format) {
        this.sigParams = null;
        this.messageDigest = null;
        this.p1363Format = p1363Format;
    }

    ECDSASignature(String digestName) {
        this(digestName, false);
    }

    ECDSASignature(String digestName, boolean p1363Format) {
        this.sigParams = null;

        try {
            this.messageDigest = MessageDigest.getInstance(digestName);
        } catch (NoSuchAlgorithmException var4) {
            throw new ProviderException(var4);
        }

        this.needsReset = false;
        this.p1363Format = p1363Format;
    }

    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        ECPublicKey key = (ECPublicKey)ECKeyFactory.toECKey(publicKey);
        if (!isCompatible(this.sigParams, key.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        } else {
            this.publicKey = key;
            this.privateKey = null;
            this.resetDigest();
        }
    }

    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        this.engineInitSign(privateKey, (SecureRandom)null);
    }

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        ECPrivateKey key = (ECPrivateKey)ECKeyFactory.toECKey(privateKey);
        if (!isCompatible(this.sigParams, key.getParams())) {
            throw new InvalidKeyException("Key params does not match signature params");
        } else {
            this.privateKey = key;
            this.publicKey = null;
            this.random = random;
            this.resetDigest();
        }
    }

    protected void resetDigest() {
        if (this.needsReset) {
            if (this.messageDigest != null) {
                this.messageDigest.reset();
            }

            this.needsReset = false;
        }

    }

    protected byte[] getDigestValue() throws SignatureException {
        this.needsReset = false;
        return this.messageDigest.digest();
    }

    protected void engineUpdate(byte b) throws SignatureException {
        this.messageDigest.update(b);
        this.needsReset = true;
    }

    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        this.messageDigest.update(b, off, len);
        this.needsReset = true;
    }

    protected void engineUpdate(ByteBuffer byteBuffer) {
        int len = byteBuffer.remaining();
        if (len > 0) {
            this.messageDigest.update(byteBuffer);
            this.needsReset = true;
        }
    }

    private static boolean isCompatible(ECParameterSpec sigParams, ECParameterSpec keyParams) {
        return sigParams == null ? true : ECUtil.equals(sigParams, keyParams);
    }

    private byte[] signDigestImpl(ECDSAOperations ops, int seedBits, byte[] digest, ECPrivateKeyImpl privImpl, SecureRandom random) throws SignatureException {
        byte[] seedBytes = new byte[(seedBits + 7) / 8];
        byte[] s = privImpl.getArrayS();
        int numAttempts = 128;
        int i = 0;

        while(i < numAttempts) {
            random.nextBytes(seedBytes);
            Seed seed = new Seed(seedBytes);

            try {
                return ops.signDigest(s, digest, seed);
            } catch (IntermediateValueException var12) {
                ++i;
            }
        }

        throw new SignatureException("Unable to produce signature after " + numAttempts + " attempts");
    }

    private Optional<byte[]> signDigestImpl(ECPrivateKey privateKey, byte[] digest, SecureRandom random) throws SignatureException {
        if (!(privateKey instanceof ECPrivateKeyImpl)) {
            return Optional.empty();
        } else {
            ECPrivateKeyImpl privImpl = (ECPrivateKeyImpl)privateKey;
            ECParameterSpec params = privateKey.getParams();
            int seedBits = params.getOrder().bitLength() + 64;
            Optional<ECDSAOperations> opsOpt = ECDSAOperations.forParameters(params);
            if (opsOpt.isEmpty()) {
                return Optional.empty();
            } else {
                byte[] sig = this.signDigestImpl((ECDSAOperations)opsOpt.get(), seedBits, digest, privImpl, random);
                return Optional.of(sig);
            }
        }
    }

    private byte[] signDigestNative(ECPrivateKey privateKey, byte[] digest, SecureRandom random) throws SignatureException {
        byte[] s = privateKey.getS().toByteArray();
        ECParameterSpec params = privateKey.getParams();
        byte[] encodedParams = ECUtil.encodeECParameterSpec((Provider)null, params);
        int orderLength = params.getOrder().bitLength();
        byte[] seed = new byte[((orderLength + 7 >> 3) + 1) * 2];
        random.nextBytes(seed);
        int timingArgument = random.nextInt();
        timingArgument |= 1;

        try {
            return signDigest(digest, s, encodedParams, seed, timingArgument);
        } catch (GeneralSecurityException var11) {
            throw new SignatureException("Could not sign data", var11);
        }
    }

    protected byte[] engineSign() throws SignatureException {
        if (this.random == null) {
            this.random = JCAUtil.getSecureRandom();
        }

        byte[] digest = this.getDigestValue();
        Optional<byte[]> sigOpt = this.signDigestImpl(this.privateKey, digest, this.random);
        byte[] sig;
        if (sigOpt.isPresent()) {
            sig = (byte[])sigOpt.get();
        } else {
            sig = this.signDigestNative(this.privateKey, digest, this.random);
        }

        return this.p1363Format ? sig : ECUtil.encodeSignature(sig);
    }

    protected boolean engineVerify(byte[] signature) throws SignatureException {
        ECParameterSpec params = this.publicKey.getParams();
        byte[] encodedParams = ECUtil.encodeECParameterSpec((Provider)null, params);
        byte[] w;
        if (this.publicKey instanceof ECPublicKeyImpl) {
            w = ((ECPublicKeyImpl)this.publicKey).getEncodedPublicValue();
        } else {
            w = ECUtil.encodePoint(this.publicKey.getW(), params.getCurve());
        }

        byte[] sig;
        if (this.p1363Format) {
            sig = signature;
        } else {
            sig = ECUtil.decodeSignature(signature);
        }

        try {
            return verifySignedDigest(sig, this.getDigestValue(), w, encodedParams);
        } catch (GeneralSecurityException var7) {
            throw new SignatureException("Could not verify signature", var7);
        }
    }

    /** @deprecated */
    @Deprecated
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new UnsupportedOperationException("setParameter() not supported");
    }

    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        if (params != null && !(params instanceof ECParameterSpec)) {
            throw new InvalidAlgorithmParameterException("No parameter accepted");
        } else {
            ECKey key = this.privateKey == null ? this.publicKey : this.privateKey;
            if (key != null && !isCompatible((ECParameterSpec)params, ((ECKey)key).getParams())) {
                throw new InvalidAlgorithmParameterException("Signature params does not match key params");
            } else {
                this.sigParams = (ECParameterSpec)params;
            }
        }
    }

    /** @deprecated */
    @Deprecated
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new UnsupportedOperationException("getParameter() not supported");
    }

    protected AlgorithmParameters engineGetParameters() {
        if (this.sigParams == null) {
            return null;
        } else {
            try {
                AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
                ap.init(this.sigParams);
                return ap;
            } catch (Exception var2) {
                throw new ProviderException("Error retrieving EC parameters", var2);
            }
        }
    }

    private static native byte[] signDigest(byte[] var0, byte[] var1, byte[] var2, byte[] var3, int var4) throws GeneralSecurityException;

    private static native boolean verifySignedDigest(byte[] var0, byte[] var1, byte[] var2, byte[] var3) throws GeneralSecurityException;

    public static final class SHA512inP1363Format extends ECDSASignature {
        public SHA512inP1363Format() {
            super("SHA-512", true);
        }
    }

    public static final class SHA512 extends ECDSASignature {
        public SHA512() {
            super("SHA-512");
        }
    }

    public static final class SHA384inP1363Format extends ECDSASignature {
        public SHA384inP1363Format() {
            super("SHA-384", true);
        }
    }

    public static final class SHA384 extends ECDSASignature {
        public SHA384() {
            super("SHA-384");
        }
    }

    public static final class SHA256inP1363Format extends ECDSASignature {
        public SHA256inP1363Format() {
            super("SHA-256", true);
        }
    }

    public static final class SHA256 extends ECDSASignature {
        public SHA256() {
            super("SHA-256");
        }
    }

    public static final class SHA224inP1363Format extends ECDSASignature {
        public SHA224inP1363Format() {
            super("SHA-224", true);
        }
    }

    public static final class SHA224 extends ECDSASignature {
        public SHA224() {
            super("SHA-224");
        }
    }

    public static final class SHA1inP1363Format extends ECDSASignature {
        public SHA1inP1363Format() {
            super("SHA1", true);
        }
    }

    public static final class SHA1 extends ECDSASignature {
        public SHA1() {
            super("SHA1");
        }
    }

    public static final class RawinP1363Format extends ECDSASignature.RawECDSA {
        public RawinP1363Format() {
            super(true);
        }
    }

    public static final class Raw extends ECDSASignature.RawECDSA {
        public Raw() {
            super(false);
        }
    }

    static class RawECDSA extends ECDSASignature {
        private static final int RAW_ECDSA_MAX = 64;
        private final byte[] precomputedDigest = new byte[64];
        private int offset = 0;

        RawECDSA(boolean p1363Format) {
            super(p1363Format);
        }

        protected void engineUpdate(byte b) throws SignatureException {
            if (this.offset >= this.precomputedDigest.length) {
                this.offset = 65;
            } else {
                this.precomputedDigest[this.offset++] = b;
            }
        }

        protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
            if (this.offset >= this.precomputedDigest.length) {
                this.offset = 65;
            } else {
                System.arraycopy(b, off, this.precomputedDigest, this.offset, len);
                this.offset += len;
            }
        }

        protected void engineUpdate(ByteBuffer byteBuffer) {
            int len = byteBuffer.remaining();
            if (len > 0) {
                if (len >= this.precomputedDigest.length - this.offset) {
                    this.offset = 65;
                } else {
                    byteBuffer.get(this.precomputedDigest, this.offset, len);
                    this.offset += len;
                }
            }
        }

        protected void resetDigest() {
            this.offset = 0;
        }

        protected byte[] getDigestValue() throws SignatureException {
            if (this.offset > 64) {
                throw new SignatureException("Message digest is too long");
            } else {
                byte[] result = new byte[this.offset];
                System.arraycopy(this.precomputedDigest, 0, result, 0, this.offset);
                this.offset = 0;
                return result;
            }
        }
    }
}
