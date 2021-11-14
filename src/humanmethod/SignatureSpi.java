package humanmethod;

import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;

public abstract class SignatureSpi {
    protected SecureRandom appRandom = null;

    public SignatureSpi() {
    }

    protected abstract void engineInitVerify(PublicKey var1) throws InvalidKeyException;

    void engineInitVerify(PublicKey publicKey, AlgorithmParameterSpec params) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            try {
                this.engineSetParameter(params);
            } catch (UnsupportedOperationException var4) {
                throw new InvalidAlgorithmParameterException(var4);
            }
        }

        this.engineInitVerify(publicKey);
    }

    protected abstract void engineInitSign(PrivateKey var1) throws InvalidKeyException;

    protected void engineInitSign(PrivateKey privateKey, SecureRandom random) throws InvalidKeyException {
        this.appRandom = random;
        this.engineInitSign(privateKey);
    }

    void engineInitSign(PrivateKey privateKey, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            try {
                this.engineSetParameter(params);
            } catch (UnsupportedOperationException var5) {
                throw new InvalidAlgorithmParameterException(var5);
            }
        }

        this.engineInitSign(privateKey, random);
    }

    protected abstract void engineUpdate(byte var1) throws SignatureException;

    protected abstract void engineUpdate(byte[] var1, int var2, int var3) throws SignatureException;

    protected void engineUpdate(ByteBuffer input) {
        if (input.hasRemaining()) {
            try {
                int chunk;
                if (input.hasArray()) {
                    byte[] b = input.array();
                    int ofs = input.arrayOffset();
                    chunk = input.position();
                    int lim = input.limit();
                    this.engineUpdate(b, ofs + chunk, lim - chunk);
                    input.position(lim);
                } else {
                    int len = input.remaining();

                    for(byte[] b = new byte[JCAUtil.getTempArraySize(len)]; len > 0; len -= chunk) {
                        chunk = Math.min(len, b.length);
                        input.get(b, 0, chunk);
                        this.engineUpdate(b, 0, chunk);
                    }
                }

            } catch (SignatureException var6) {
                throw new ProviderException("update() failed", var6);
            }
        }
    }

    protected abstract byte[] engineSign() throws SignatureException;

    protected int engineSign(byte[] outbuf, int offset, int len) throws SignatureException {
        byte[] sig = this.engineSign();
        if (len < sig.length) {
            throw new SignatureException("partial signatures not returned");
        } else if (outbuf.length - offset < sig.length) {
            throw new SignatureException("insufficient space in the output buffer to store the signature");
        } else {
            System.arraycopy(sig, 0, outbuf, offset, sig.length);
            return sig.length;
        }
    }

    protected abstract boolean engineVerify(byte[] var1) throws SignatureException;

    protected boolean engineVerify(byte[] sigBytes, int offset, int length) throws SignatureException {
        byte[] sigBytesCopy = new byte[length];
        System.arraycopy(sigBytes, offset, sigBytesCopy, 0, length);
        return this.engineVerify(sigBytesCopy);
    }

    /** @deprecated */
    @Deprecated
    protected abstract void engineSetParameter(String var1, Object var2) throws InvalidParameterException;

    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        throw new UnsupportedOperationException();
    }

    protected AlgorithmParameters engineGetParameters() {
        throw new UnsupportedOperationException();
    }

    /** @deprecated */
    @Deprecated
    protected abstract Object engineGetParameter(String var1) throws InvalidParameterException;

    public Object clone() throws CloneNotSupportedException {
        if (this instanceof Cloneable) {
            return super.clone();
        } else {
            throw new CloneNotSupportedException();
        }
    }
}