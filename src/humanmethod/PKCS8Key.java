package humanmethod;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectStreamException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyRep;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.KeyRep.Type;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class PKCS8Key implements PrivateKey {
    private static final long serialVersionUID = -3836890099307167124L;
    protected AlgorithmId algid;
    protected byte[] key;
    protected byte[] encodedKey;
    public static final BigInteger version;

    public PKCS8Key() {
    }

    private PKCS8Key(AlgorithmId algid, byte[] key) throws InvalidKeyException {
        this.algid = algid;
        this.key = key;
        this.encode();
    }

    public static PKCS8Key parse(DerValue in) throws IOException {
        PrivateKey key = parseKey(in);
        if (key instanceof PKCS8Key) {
            return (PKCS8Key)key;
        } else {
            throw new IOException("Provider did not return PKCS8Key");
        }
    }

    public static PrivateKey parseKey(DerValue in) throws IOException {
        if (in.tag != 48) {
            throw new IOException("corrupt private key");
        } else {
            BigInteger parsedVersion = in.data.getBigInteger();
            if (!version.equals(parsedVersion)) {
                throw new IOException("version mismatch: (supported: " + Debug.toHexString(version) + ", parsed: " + Debug.toHexString(parsedVersion));
            } else {
                AlgorithmId algorithm = AlgorithmId.parse(in.data.getDerValue());

                PrivateKey privKey;
                try {
                    privKey = buildPKCS8Key(algorithm, in.data.getOctetString());
                } catch (InvalidKeyException var5) {
                    throw new IOException("corrupt private key");
                }

                if (in.data.available() != 0) {
                    throw new IOException("excess private key");
                } else {
                    return privKey;
                }
            }
        }
    }

    protected void parseKeyBits() throws IOException, InvalidKeyException {
        this.encode();
    }

    static PrivateKey buildPKCS8Key(AlgorithmId algid, byte[] key) throws IOException, InvalidKeyException {
        DerOutputStream pkcs8EncodedKeyStream = new DerOutputStream();
        encode(pkcs8EncodedKeyStream, algid, key);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(pkcs8EncodedKeyStream.toByteArray());

        try {
            KeyFactory keyFac = KeyFactory.getInstance(algid.getName());
            return keyFac.generatePrivate(pkcs8KeySpec);
        } catch (NoSuchAlgorithmException var11) {
        } catch (InvalidKeySpecException var12) {
        }

        String classname = "";

        try {
            Provider sunProvider = Security.getProvider("SUN");
            if (sunProvider == null) {
                throw new InstantiationException();
            }

            classname = sunProvider.getProperty("PrivateKey.PKCS#8." + algid.getName());
            if (classname == null) {
                throw new InstantiationException();
            }

            Class keyClass = null;

            try {
                keyClass = Class.forName(classname);
            } catch (ClassNotFoundException var13) {
                ClassLoader cl = ClassLoader.getSystemClassLoader();
                if (cl != null) {
                    keyClass = cl.loadClass(classname);
                }
            }

            Object inst = keyClass != null ? keyClass.newInstance() : null;
            if (inst instanceof PKCS8Key) {
                PKCS8Key result = (PKCS8Key)inst;
                result.algid = algid;
                result.key = key;
                result.parseKeyBits();
                return result;
            }
        } catch (ClassNotFoundException var14) {
        } catch (InstantiationException var15) {
        } catch (IllegalAccessException var16) {
            throw new IOException(classname + " [internal error]");
        }

        PKCS8Key result = new PKCS8Key();
        result.algid = algid;
        result.key = key;
        return result;
    }

    public String getAlgorithm() {
        return this.algid.getName();
    }

    public AlgorithmId getAlgorithmId() {
        return this.algid;
    }

    public final void encode(DerOutputStream out) throws IOException {
        encode(out, this.algid, this.key);
    }

    public synchronized byte[] getEncoded() {
        byte[] result = null;

        try {
            result = this.encode();
        } catch (InvalidKeyException var3) {
        }

        return result;
    }

    public String getFormat() {
        return "PKCS#8";
    }

    public byte[] encode() throws InvalidKeyException {
        if (this.encodedKey == null) {
            try {
                DerOutputStream out = new DerOutputStream();
                this.encode(out);
                this.encodedKey = out.toByteArray();
            } catch (IOException var2) {
                throw new InvalidKeyException("IOException : " + var2.getMessage());
            }
        }

        return (byte[])this.encodedKey.clone();
    }

    public void decode(InputStream in) throws InvalidKeyException {
        try {
            DerValue val = new DerValue(in);
            if (val.tag != 48) {
                throw new InvalidKeyException("invalid key format");
            } else {
                BigInteger version = val.data.getBigInteger();
                if (!version.equals(PKCS8Key.version)) {
                    throw new IOException("version mismatch: (supported: " + Debug.toHexString(PKCS8Key.version) + ", parsed: " + Debug.toHexString(version));
                } else {
                    this.algid = AlgorithmId.parse(val.data.getDerValue());
                    this.key = val.data.getOctetString();
                    this.parseKeyBits();
                    if (val.data.available() != 0) {
                    }

                }
            }
        } catch (IOException var4) {
            throw new InvalidKeyException("IOException : " + var4.getMessage());
        }
    }

    public void decode(byte[] encodedKey) throws InvalidKeyException {
        this.decode((InputStream)(new ByteArrayInputStream(encodedKey)));
    }

    protected Object writeReplace() throws ObjectStreamException {
        return new KeyRep(Type.PRIVATE, this.getAlgorithm(), this.getFormat(), this.getEncoded());
    }

    private void readObject(ObjectInputStream stream) throws IOException {
        try {
            this.decode((InputStream)stream);
        } catch (InvalidKeyException var3) {
            var3.printStackTrace();
            throw new IOException("deserialized key is invalid: " + var3.getMessage());
        }
    }

    static void encode(DerOutputStream out, AlgorithmId algid, byte[] key) throws IOException {
        DerOutputStream tmp = new DerOutputStream();
        tmp.putInteger(version);
        algid.encode(tmp);
        tmp.putOctetString(key);
        out.write((byte)48, tmp);
    }

    public boolean equals(Object object) {
        if (this == object) {
            return true;
        } else if (object instanceof Key) {
            byte[] b1;
            if (this.encodedKey != null) {
                b1 = this.encodedKey;
            } else {
                b1 = this.getEncoded();
            }

            byte[] b2 = ((Key)object).getEncoded();
            return MessageDigest.isEqual(b1, b2);
        } else {
            return false;
        }
    }

    public int hashCode() {
        int retval = 0;
        byte[] b1 = this.getEncoded();

        for(int i = 1; i < b1.length; ++i) {
            retval += b1[i] * i;
        }

        return retval;
    }

    static {
        version = BigInteger.ZERO;
    }
}
