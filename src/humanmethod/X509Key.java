package humanmethod;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


public class X509Key implements PublicKey {
    private static final long serialVersionUID = -5359250853002055002L;
    protected AlgorithmId algid;
    /** @deprecated */
    @Deprecated
    protected byte[] key = null;
    /** @deprecated */
    @Deprecated
    private int unusedBits = 0;
    private BitArray bitStringKey = null;
    protected byte[] encodedKey;

    public X509Key() {
    }

    private X509Key(AlgorithmId algid, BitArray key) throws InvalidKeyException {
        this.algid = algid;
        this.setKey(key);
        this.encode();
    }

    protected void setKey(BitArray key) {
        this.bitStringKey = (BitArray)key.clone();
        this.key = key.toByteArray();
        int remaining = key.length() % 8;
        this.unusedBits = remaining == 0 ? 0 : 8 - remaining;
    }

    protected BitArray getKey() {
        this.bitStringKey = new BitArray(this.key.length * 8 - this.unusedBits, this.key);
        return (BitArray)this.bitStringKey.clone();
    }

    public static PublicKey parse(DerValue in) throws IOException {
        if (in.tag != 48) {
            throw new IOException("corrupt subject key");
        } else {
            AlgorithmId algorithm = AlgorithmId.parse(in.data.getDerValue());

            PublicKey subjectKey;
            try {
                subjectKey = buildX509Key(algorithm, in.data.getUnalignedBitString());
            } catch (InvalidKeyException var4) {
                throw new IOException("subject key, " + var4.getMessage(), var4);
            }

            if (in.data.available() != 0) {
                throw new IOException("excess subject key");
            } else {
                return subjectKey;
            }
        }
    }

    protected void parseKeyBits() throws IOException, InvalidKeyException {
        this.encode();
    }

    static PublicKey buildX509Key(AlgorithmId algid, BitArray key) throws IOException, InvalidKeyException {
        DerOutputStream x509EncodedKeyStream = new DerOutputStream();
        encode(x509EncodedKeyStream, algid, key);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(x509EncodedKeyStream.toByteArray());

        try {
            KeyFactory keyFac = KeyFactory.getInstance(algid.getName());
            return keyFac.generatePublic(x509KeySpec);
        } catch (NoSuchAlgorithmException var15) {
            String classname = "";

            try {
                Provider sunProvider = Security.getProvider("SUN");
                if (sunProvider == null) {
                    throw new InstantiationException();
                }

                classname = sunProvider.getProperty("PublicKey.X.509." + algid.getName());
                if (classname == null) {
                    throw new InstantiationException();
                }

                Class keyClass = null;

                try {
                    keyClass = Class.forName(classname);
                } catch (ClassNotFoundException var11) {
                    ClassLoader cl = ClassLoader.getSystemClassLoader();
                    if (cl != null) {
                        keyClass = cl.loadClass(classname);
                    }
                }

                Object inst = keyClass != null ? keyClass.newInstance() : null;
                if (inst instanceof X509Key) {
                    X509Key result = (X509Key)inst;
                    result.algid = algid;
                    result.setKey(key);
                    result.parseKeyBits();
                    return result;
                }
            } catch (ClassNotFoundException var12) {
            } catch (InstantiationException var13) {
            } catch (IllegalAccessException var14) {
                throw new IOException(classname + " [internal error]");
            }

            X509Key result = new X509Key(algid, key);
            return result;
        } catch (InvalidKeySpecException var16) {
            throw new InvalidKeyException(var16.getMessage(), var16);
        }
    }

    public String getAlgorithm() {
        return this.algid.getName();
    }

    public AlgorithmId getAlgorithmId() {
        return this.algid;
    }

    public final void encode(DerOutputStream out) throws IOException {
        encode(out, this.algid, this.getKey());
    }

    public byte[] getEncoded() {
        try {
            return (byte[])this.getEncodedInternal().clone();
        } catch (InvalidKeyException var2) {
            return null;
        }
    }

    public byte[] getEncodedInternal() throws InvalidKeyException {
        byte[] encoded = this.encodedKey;
        if (encoded == null) {
            try {
                DerOutputStream out = new DerOutputStream();
                this.encode(out);
                encoded = out.toByteArray();
            } catch (IOException var3) {
                throw new InvalidKeyException("IOException : " + var3.getMessage());
            }

            this.encodedKey = encoded;
        }

        return encoded;
    }

    public String getFormat() {
        return "X.509";
    }

    public byte[] encode() throws InvalidKeyException {
        return (byte[])this.getEncodedInternal().clone();
    }

    public String toString() {
        HexDumpEncoder encoder = new HexDumpEncoder();
        return "algorithm = " + this.algid.toString() + ", unparsed keybits = \n" + encoder.encodeBuffer(this.key);
    }

    public void decode(InputStream in) throws InvalidKeyException {
        try {
            DerValue val = new DerValue(in);
            if (val.tag != 48) {
                throw new InvalidKeyException("invalid key format");
            } else {
                this.algid = AlgorithmId.parse(val.data.getDerValue());
                this.setKey(val.data.getUnalignedBitString());
                this.parseKeyBits();
                if (val.data.available() != 0) {
                    throw new InvalidKeyException("excess key data");
                }
            }
        } catch (IOException var4) {
            throw new InvalidKeyException("IOException: " + var4.getMessage());
        }
    }

    public void decode(byte[] encodedKey) throws InvalidKeyException {
        this.decode((InputStream)(new ByteArrayInputStream(encodedKey)));
    }

    private void writeObject(ObjectOutputStream stream) throws IOException {
        stream.write(this.getEncoded());
    }

    private void readObject(ObjectInputStream stream) throws IOException {
        try {
            this.decode((InputStream)stream);
        } catch (InvalidKeyException var3) {
            var3.printStackTrace();
            throw new IOException("deserialized key is invalid: " + var3.getMessage());
        }
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (!(obj instanceof Key)) {
            return false;
        } else {
            try {
                byte[] thisEncoded = this.getEncodedInternal();
                byte[] otherEncoded;
                if (obj instanceof X509Key) {
                    otherEncoded = ((X509Key)obj).getEncodedInternal();
                } else {
                    otherEncoded = ((Key)obj).getEncoded();
                }

                return Arrays.equals(thisEncoded, otherEncoded);
            } catch (InvalidKeyException var4) {
                return false;
            }
        }
    }

    public int hashCode() {
        try {
            byte[] b1 = this.getEncodedInternal();
            int r = b1.length;

            for(int i = 0; i < b1.length; ++i) {
                r += (b1[i] & 255) * 37;
            }

            return r;
        } catch (InvalidKeyException var4) {
            return 0;
        }
    }

    static void encode(DerOutputStream out, AlgorithmId algid, BitArray key) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        algid.encode(tmp);
        tmp.putUnalignedBitString(key);
        out.write((byte)48, tmp);
    }
}
