package humanmethod;

import java.io.IOException;
import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public final class ECPrivateKeyImpl extends PKCS8Key implements ECPrivateKey {
    private static final long serialVersionUID = 88695385615075129L;
    private BigInteger s;
    private byte[] arrayS;
    private ECParameterSpec params;

    ECPrivateKeyImpl(byte[] encoded) throws InvalidKeyException {
        this.decode(encoded);
    }

    ECPrivateKeyImpl(BigInteger s, ECParameterSpec params) throws InvalidKeyException {
        this.s = s;
        this.params = params;
        this.makeEncoding(s);
    }

    ECPrivateKeyImpl(byte[] s, ECParameterSpec params) throws InvalidKeyException {
        this.arrayS = (byte[])s.clone();
        this.params = params;
        this.makeEncoding(s);
    }

    private void makeEncoding(byte[] s) throws InvalidKeyException {
        this.algid = new AlgorithmId(AlgorithmId.EC_oid, ECParameters.getAlgorithmParameters(this.params));

        try {
            DerOutputStream out = new DerOutputStream();
            out.putInteger(1);
            byte[] privBytes = (byte[])s.clone();
            ArrayUtil.reverse(privBytes);
            out.putOctetString(privBytes);
            DerValue val = new DerValue((byte)48, out.toByteArray());
            this.key = val.toByteArray();
        } catch (IOException var5) {
            throw new InvalidKeyException(var5);
        }
    }

    private void makeEncoding(BigInteger s) throws InvalidKeyException {
        this.algid = new AlgorithmId(AlgorithmId.EC_oid, ECParameters.getAlgorithmParameters(this.params));

        try {
            byte[] sArr = s.toByteArray();
            int numOctets = (this.params.getOrder().bitLength() + 7) / 8;
            byte[] sOctets = new byte[numOctets];
            int inPos = Math.max(sArr.length - sOctets.length, 0);
            int outPos = Math.max(sOctets.length - sArr.length, 0);
            int length = Math.min(sArr.length, sOctets.length);
            System.arraycopy(sArr, inPos, sOctets, outPos, length);
            DerOutputStream out = new DerOutputStream();
            out.putInteger(1);
            out.putOctetString(sOctets);
            DerValue val = new DerValue((byte)48, out.toByteArray());
            this.key = val.toByteArray();
        } catch (IOException var10) {
            throw new InvalidKeyException(var10);
        }
    }

    public String getAlgorithm() {
        return "EC";
    }

    public BigInteger getS() {
        if (this.s == null) {
            byte[] arrCopy = (byte[])this.arrayS.clone();
            ArrayUtil.reverse(arrCopy);
            this.s = new BigInteger(1, arrCopy);
        }

        return this.s;
    }

    public byte[] getArrayS() {
        if (this.arrayS == null) {
            byte[] arr = this.getS().toByteArray();
            ArrayUtil.reverse(arr);
            int byteLength = (this.params.getOrder().bitLength() + 7) / 8;
            this.arrayS = new byte[byteLength];
            int length = Math.min(byteLength, arr.length);
            System.arraycopy(arr, 0, this.arrayS, 0, length);
        }

        return (byte[])this.arrayS.clone();
    }

    public ECParameterSpec getParams() {
        return this.params;
    }

    protected void parseKeyBits() throws InvalidKeyException {
        try {
            DerInputStream in = new DerInputStream(this.key);
            DerValue derValue = in.getDerValue();
            if (derValue.tag != 48) {
                throw new IOException("Not a SEQUENCE");
            } else {
                DerInputStream data = derValue.data;
                int version = data.getInteger();
                if (version != 1) {
                    throw new IOException("Version must be 1");
                } else {
                    byte[] privData = data.getOctetString();
                    ArrayUtil.reverse(privData);
                    this.arrayS = privData;

                    DerValue value;
                    do {
                        if (data.available() == 0) {
                            AlgorithmParameters algParams = this.algid.getParameters();
                            if (algParams == null) {
                                throw new InvalidKeyException("EC domain parameters must be encoded in the algorithm identifier");
                            }

                            this.params = (ECParameterSpec)algParams.getParameterSpec(ECParameterSpec.class);
                            return;
                        }

                        value = data.getDerValue();
                    } while(value.isContextSpecific((byte)0) || value.isContextSpecific((byte)1));

                    throw new InvalidKeyException("Unexpected value: " + value);
                }
            }
        } catch (IOException var7) {
            throw new InvalidKeyException("Invalid EC private key", var7);
        } catch (InvalidParameterSpecException var8) {
            throw new InvalidKeyException("Invalid EC private key", var8);
        }
    }
}
