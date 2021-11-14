package humanmethod;

import java.io.IOException;
import java.io.ObjectStreamException;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyRep;
import java.security.KeyRep.Type;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.InvalidParameterSpecException;

public final class ECPublicKeyImpl extends X509Key implements ECPublicKey {
    private static final long serialVersionUID = -2462037275160462289L;
    private ECPoint w;
    private ECParameterSpec params;

    ECPublicKeyImpl(ECPoint w, ECParameterSpec params) throws InvalidKeyException {
        this.w = w;
        this.params = params;
        this.algid = new AlgorithmId(AlgorithmId.EC_oid, ECParameters.getAlgorithmParameters(params));
        this.key = ECUtil.encodePoint(w, params.getCurve());
    }

    ECPublicKeyImpl(byte[] encoded) throws InvalidKeyException {
        this.decode(encoded);
    }

    public String getAlgorithm() {
        return "EC";
    }

    public ECPoint getW() {
        return this.w;
    }

    public ECParameterSpec getParams() {
        return this.params;
    }

    public byte[] getEncodedPublicValue() {
        return (byte[])this.key.clone();
    }

    protected void parseKeyBits() throws InvalidKeyException {
        AlgorithmParameters algParams = this.algid.getParameters();
        if (algParams == null) {
            throw new InvalidKeyException("EC domain parameters must be encoded in the algorithm identifier");
        } else {
            try {
                this.params = (ECParameterSpec)algParams.getParameterSpec(ECParameterSpec.class);
                this.w = ECUtil.decodePoint(this.key, this.params.getCurve());
            } catch (IOException var3) {
                throw new InvalidKeyException("Invalid EC key", var3);
            } catch (InvalidParameterSpecException var4) {
                throw new InvalidKeyException("Invalid EC key", var4);
            }
        }
    }

    public String toString() {
        int var10000 = this.params.getCurve().getField().getFieldSize();
        return "Sun EC public key, " + var10000 + " bits\n  public x coord: " + this.w.getAffineX() + "\n  public y coord: " + this.w.getAffineY() + "\n  parameters: " + this.params;
    }

    protected Object writeReplace() throws ObjectStreamException {
        return new KeyRep(Type.PUBLIC, this.getAlgorithm(), this.getFormat(), this.getEncoded());
    }
}
