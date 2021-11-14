package humanmethod;

import java.io.IOException;
import java.io.OutputStream;
import java.io.Serializable;
import java.security.AlgorithmParameters;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Locale;
import java.util.Map;


public class AlgorithmId implements Serializable, DerEncoder {
    private static final long serialVersionUID = 7205873507486557157L;
    private ObjectIdentifier algid;
    private AlgorithmParameters algParams;
    private boolean constructedFromDer = true;
    protected DerValue params;
    private static volatile Map<String, ObjectIdentifier> oidTable;
    private static final Map<ObjectIdentifier, String> nameTable;
    public static final ObjectIdentifier MD2_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 2, 2});
    public static final ObjectIdentifier MD5_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 2, 5});
    public static final ObjectIdentifier SHA_oid = ObjectIdentifier.newInternal(new int[]{1, 3, 14, 3, 2, 26});
    public static final ObjectIdentifier SHA224_oid = ObjectIdentifier.newInternal(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 4});
    public static final ObjectIdentifier SHA256_oid = ObjectIdentifier.newInternal(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 1});
    public static final ObjectIdentifier SHA384_oid = ObjectIdentifier.newInternal(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 2});
    public static final ObjectIdentifier SHA512_oid = ObjectIdentifier.newInternal(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 3});
    public static final ObjectIdentifier SHA512_224_oid = ObjectIdentifier.newInternal(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 5});
    public static final ObjectIdentifier SHA512_256_oid = ObjectIdentifier.newInternal(new int[]{2, 16, 840, 1, 101, 3, 4, 2, 6});
    private static final int[] DH_data = new int[]{1, 2, 840, 113549, 1, 3, 1};
    private static final int[] DH_PKIX_data = new int[]{1, 2, 840, 10046, 2, 1};
    private static final int[] DSA_OIW_data = new int[]{1, 3, 14, 3, 2, 12};
    private static final int[] DSA_PKIX_data = new int[]{1, 2, 840, 10040, 4, 1};
    private static final int[] RSA_data = new int[]{2, 5, 8, 1, 1};
    public static final ObjectIdentifier DH_oid;
    public static final ObjectIdentifier DH_PKIX_oid;
    public static final ObjectIdentifier DSA_oid;
    public static final ObjectIdentifier DSA_OIW_oid;
    public static final ObjectIdentifier EC_oid = oid(1, 2, 840, 10045, 2, 1);
    public static final ObjectIdentifier ECDH_oid = oid(1, 3, 132, 1, 12);
    public static final ObjectIdentifier RSA_oid;
    public static final ObjectIdentifier RSAEncryption_oid = oid(1, 2, 840, 113549, 1, 1, 1);
    public static final ObjectIdentifier RSAES_OAEP_oid = oid(1, 2, 840, 113549, 1, 1, 7);
    public static final ObjectIdentifier mgf1_oid = oid(1, 2, 840, 113549, 1, 1, 8);
    public static final ObjectIdentifier RSASSA_PSS_oid = oid(1, 2, 840, 113549, 1, 1, 10);
    public static final ObjectIdentifier AES_oid = oid(2, 16, 840, 1, 101, 3, 4, 1);
    private static final int[] md2WithRSAEncryption_data = new int[]{1, 2, 840, 113549, 1, 1, 2};
    private static final int[] md5WithRSAEncryption_data = new int[]{1, 2, 840, 113549, 1, 1, 4};
    private static final int[] sha1WithRSAEncryption_data = new int[]{1, 2, 840, 113549, 1, 1, 5};
    private static final int[] sha1WithRSAEncryption_OIW_data = new int[]{1, 3, 14, 3, 2, 29};
    private static final int[] sha224WithRSAEncryption_data = new int[]{1, 2, 840, 113549, 1, 1, 14};
    private static final int[] sha256WithRSAEncryption_data = new int[]{1, 2, 840, 113549, 1, 1, 11};
    private static final int[] sha384WithRSAEncryption_data = new int[]{1, 2, 840, 113549, 1, 1, 12};
    private static final int[] sha512WithRSAEncryption_data = new int[]{1, 2, 840, 113549, 1, 1, 13};
    private static final int[] shaWithDSA_OIW_data = new int[]{1, 3, 14, 3, 2, 13};
    private static final int[] sha1WithDSA_OIW_data = new int[]{1, 3, 14, 3, 2, 27};
    private static final int[] dsaWithSHA1_PKIX_data = new int[]{1, 2, 840, 10040, 4, 3};
    public static final ObjectIdentifier md2WithRSAEncryption_oid;
    public static final ObjectIdentifier md5WithRSAEncryption_oid;
    public static final ObjectIdentifier sha1WithRSAEncryption_oid;
    public static final ObjectIdentifier sha1WithRSAEncryption_OIW_oid;
    public static final ObjectIdentifier sha224WithRSAEncryption_oid;
    public static final ObjectIdentifier sha256WithRSAEncryption_oid;
    public static final ObjectIdentifier sha384WithRSAEncryption_oid;
    public static final ObjectIdentifier sha512WithRSAEncryption_oid;
    public static final ObjectIdentifier sha512_224WithRSAEncryption_oid = oid(1, 2, 840, 113549, 1, 1, 15);
    public static final ObjectIdentifier sha512_256WithRSAEncryption_oid = oid(1, 2, 840, 113549, 1, 1, 16);
    public static final ObjectIdentifier shaWithDSA_OIW_oid;
    public static final ObjectIdentifier sha1WithDSA_OIW_oid;
    public static final ObjectIdentifier sha1WithDSA_oid;
    public static final ObjectIdentifier sha224WithDSA_oid = oid(2, 16, 840, 1, 101, 3, 4, 3, 1);
    public static final ObjectIdentifier sha256WithDSA_oid = oid(2, 16, 840, 1, 101, 3, 4, 3, 2);
    public static final ObjectIdentifier sha1WithECDSA_oid = oid(1, 2, 840, 10045, 4, 1);
    public static final ObjectIdentifier sha224WithECDSA_oid = oid(1, 2, 840, 10045, 4, 3, 1);
    public static final ObjectIdentifier sha256WithECDSA_oid = oid(1, 2, 840, 10045, 4, 3, 2);
    public static final ObjectIdentifier sha384WithECDSA_oid = oid(1, 2, 840, 10045, 4, 3, 3);
    public static final ObjectIdentifier sha512WithECDSA_oid = oid(1, 2, 840, 10045, 4, 3, 4);
    public static final ObjectIdentifier specifiedWithECDSA_oid = oid(1, 2, 840, 10045, 4, 3);
    public static final ObjectIdentifier pbeWithMD5AndDES_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 1, 5, 3});
    public static final ObjectIdentifier pbeWithMD5AndRC2_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 1, 5, 6});
    public static final ObjectIdentifier pbeWithSHA1AndDES_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 1, 5, 10});
    public static final ObjectIdentifier pbeWithSHA1AndRC2_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 1, 5, 11});
    public static ObjectIdentifier pbeWithSHA1AndDESede_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 1, 12, 1, 3});
    public static ObjectIdentifier pbeWithSHA1AndRC2_40_oid = ObjectIdentifier.newInternal(new int[]{1, 2, 840, 113549, 1, 12, 1, 6});

    /** @deprecated */
    @Deprecated
    public AlgorithmId() {
    }

    public AlgorithmId(ObjectIdentifier oid) {
        this.algid = oid;
    }

    public AlgorithmId(ObjectIdentifier oid, AlgorithmParameters algparams) {
        this.algid = oid;
        this.algParams = algparams;
        this.constructedFromDer = false;
    }

    private AlgorithmId(ObjectIdentifier oid, DerValue params) throws IOException {
        this.algid = oid;
        this.params = params;
        if (this.params != null) {
            this.decodeParams();
        }

    }

    protected void decodeParams() throws IOException {
        String algidName = this.getName();

        try {
            this.algParams = AlgorithmParameters.getInstance(algidName);
        } catch (NoSuchAlgorithmException var3) {
            this.algParams = null;
            return;
        }

        this.algParams.init(this.params.toByteArray());
    }

    public final void encode(DerOutputStream out) throws IOException {
        this.derEncode(out);
    }

    public void derEncode(OutputStream out) throws IOException {
        DerOutputStream bytes = new DerOutputStream();
        DerOutputStream tmp = new DerOutputStream();
        bytes.putOID(this.algid);
        if (!this.constructedFromDer) {
            if (this.algParams != null) {
                this.params = new DerValue(this.algParams.getEncoded());
            } else {
                this.params = null;
            }
        }

        if (this.params == null) {
            if (!this.algid.equals(RSASSA_PSS_oid)) {
                bytes.putNull();
            }
        } else {
            bytes.putDerValue(this.params);
        }

        tmp.write((byte)48, bytes);
        out.write(tmp.toByteArray());
    }

    public final byte[] encode() throws IOException {
        DerOutputStream out = new DerOutputStream();
        this.derEncode(out);
        return out.toByteArray();
    }

    public final ObjectIdentifier getOID() {
        return this.algid;
    }

    public String getName() {
        String algName = (String)nameTable.get(this.algid);
        if (algName != null) {
            return algName;
        } else {
            if (this.params != null && this.algid.equals(specifiedWithECDSA_oid)) {
                try {
                    AlgorithmId paramsId = parse(new DerValue(this.params.toByteArray()));
                    String paramsName = paramsId.getName();
                    algName = makeSigAlg(paramsName, "EC");
                } catch (IOException var4) {
                }
            }

            return algName == null ? this.algid.toString() : algName;
        }
    }

    public AlgorithmParameters getParameters() {
        return this.algParams;
    }

    public byte[] getEncodedParams() throws IOException {
        return this.params != null && !this.algid.equals(specifiedWithECDSA_oid) ? this.params.toByteArray() : null;
    }

    public boolean equals(AlgorithmId other) {
        boolean paramsEqual = this.params == null ? other.params == null : this.params.equals(other.params);
        return this.algid.equals(other.algid) && paramsEqual;
    }

    public boolean equals(Object other) {
        if (this == other) {
            return true;
        } else if (other instanceof AlgorithmId) {
            return this.equals((AlgorithmId)other);
        } else {
            return other instanceof ObjectIdentifier ? this.equals((ObjectIdentifier)other) : false;
        }
    }

    public final boolean equals(ObjectIdentifier id) {
        return this.algid.equals(id);
    }

    public int hashCode() {
        StringBuilder sbuf = new StringBuilder();
        sbuf.append(this.algid.toString());
        sbuf.append(this.paramsToString());
        return sbuf.toString().hashCode();
    }

    protected String paramsToString() {
        if (this.params == null) {
            return "";
        } else {
            return this.algParams != null ? this.algParams.toString() : ", params unparsed";
        }
    }

    public String toString() {
        return this.getName() + this.paramsToString();
    }

    public static AlgorithmId parse(DerValue val) throws IOException {
        if (val.tag != 48) {
            throw new IOException("algid parse error, not a sequence");
        } else {
            DerInputStream in = val.toDerInputStream();
            ObjectIdentifier algid = in.getOID();
            DerValue params;
            if (in.available() == 0) {
                params = null;
            } else {
                params = in.getDerValue();
                if (params.tag == 5) {
                    if (params.length() != 0) {
                        throw new IOException("invalid NULL");
                    }

                    params = null;
                }

                if (in.available() != 0) {
                    throw new IOException("Invalid AlgorithmIdentifier: extra data");
                }
            }

            return new AlgorithmId(algid, params);
        }
    }

    /** @deprecated */
    @Deprecated
    public static AlgorithmId getAlgorithmId(String algname) throws NoSuchAlgorithmException {
        return get(algname);
    }

    public static AlgorithmId get(String algname) throws NoSuchAlgorithmException {
        ObjectIdentifier oid;
        try {
            oid = algOID(algname);
        } catch (IOException var3) {
            throw new NoSuchAlgorithmException("Invalid ObjectIdentifier " + algname);
        }

        if (oid == null) {
            throw new NoSuchAlgorithmException("unrecognized algorithm name: " + algname);
        } else {
            return new AlgorithmId(oid);
        }
    }

    public static AlgorithmId get(AlgorithmParameters algparams) throws NoSuchAlgorithmException {
        String algname = algparams.getAlgorithm();

        ObjectIdentifier oid;
        try {
            oid = algOID(algname);
        } catch (IOException var4) {
            throw new NoSuchAlgorithmException("Invalid ObjectIdentifier " + algname);
        }

        if (oid == null) {
            throw new NoSuchAlgorithmException("unrecognized algorithm name: " + algname);
        } else {
            return new AlgorithmId(oid, algparams);
        }
    }

    private static ObjectIdentifier algOID(String name) throws IOException {
        if (name.indexOf(46) != -1) {
            return name.startsWith("OID.") ? new ObjectIdentifier(name.substring("OID.".length())) : new ObjectIdentifier(name);
        } else if (name.equalsIgnoreCase("MD5")) {
            return MD5_oid;
        } else if (name.equalsIgnoreCase("MD2")) {
            return MD2_oid;
        } else if (!name.equalsIgnoreCase("SHA") && !name.equalsIgnoreCase("SHA1") && !name.equalsIgnoreCase("SHA-1")) {
            if (!name.equalsIgnoreCase("SHA-256") && !name.equalsIgnoreCase("SHA256")) {
                if (!name.equalsIgnoreCase("SHA-384") && !name.equalsIgnoreCase("SHA384")) {
                    if (!name.equalsIgnoreCase("SHA-512") && !name.equalsIgnoreCase("SHA512")) {
                        if (!name.equalsIgnoreCase("SHA-224") && !name.equalsIgnoreCase("SHA224")) {
                            if (!name.equalsIgnoreCase("SHA-512/224") && !name.equalsIgnoreCase("SHA512/224")) {
                                if (!name.equalsIgnoreCase("SHA-512/256") && !name.equalsIgnoreCase("SHA512/256")) {
                                    if (name.equalsIgnoreCase("RSA")) {
                                        return RSAEncryption_oid;
                                    } else if (name.equalsIgnoreCase("RSASSA-PSS")) {
                                        return RSASSA_PSS_oid;
                                    } else if (name.equalsIgnoreCase("RSAES-OAEP")) {
                                        return RSAES_OAEP_oid;
                                    } else if (!name.equalsIgnoreCase("Diffie-Hellman") && !name.equalsIgnoreCase("DH")) {
                                        if (name.equalsIgnoreCase("DSA")) {
                                            return DSA_oid;
                                        } else if (name.equalsIgnoreCase("EC")) {
                                            return EC_oid;
                                        } else if (name.equalsIgnoreCase("ECDH")) {
                                            return ECDH_oid;
                                        } else if (name.equalsIgnoreCase("AES")) {
                                            return AES_oid;
                                        } else if (!name.equalsIgnoreCase("MD5withRSA") && !name.equalsIgnoreCase("MD5/RSA")) {
                                            if (!name.equalsIgnoreCase("MD2withRSA") && !name.equalsIgnoreCase("MD2/RSA")) {
                                                if (!name.equalsIgnoreCase("SHAwithDSA") && !name.equalsIgnoreCase("SHA1withDSA") && !name.equalsIgnoreCase("SHA/DSA") && !name.equalsIgnoreCase("SHA1/DSA") && !name.equalsIgnoreCase("DSAWithSHA1") && !name.equalsIgnoreCase("DSS") && !name.equalsIgnoreCase("SHA-1/DSA")) {
                                                    if (name.equalsIgnoreCase("SHA224WithDSA")) {
                                                        return sha224WithDSA_oid;
                                                    } else if (name.equalsIgnoreCase("SHA256WithDSA")) {
                                                        return sha256WithDSA_oid;
                                                    } else if (!name.equalsIgnoreCase("SHA1WithRSA") && !name.equalsIgnoreCase("SHA1/RSA")) {
                                                        if (!name.equalsIgnoreCase("SHA1withECDSA") && !name.equalsIgnoreCase("ECDSA")) {
                                                            if (name.equalsIgnoreCase("SHA224withECDSA")) {
                                                                return sha224WithECDSA_oid;
                                                            } else if (name.equalsIgnoreCase("SHA256withECDSA")) {
                                                                return sha256WithECDSA_oid;
                                                            } else if (name.equalsIgnoreCase("SHA384withECDSA")) {
                                                                return sha384WithECDSA_oid;
                                                            } else {
                                                                return name.equalsIgnoreCase("SHA512withECDSA") ? sha512WithECDSA_oid : (ObjectIdentifier)oidTable().get(name.toUpperCase(Locale.ENGLISH));
                                                            }
                                                        } else {
                                                            return sha1WithECDSA_oid;
                                                        }
                                                    } else {
                                                        return sha1WithRSAEncryption_oid;
                                                    }
                                                } else {
                                                    return sha1WithDSA_oid;
                                                }
                                            } else {
                                                return md2WithRSAEncryption_oid;
                                            }
                                        } else {
                                            return md5WithRSAEncryption_oid;
                                        }
                                    } else {
                                        return DH_oid;
                                    }
                                } else {
                                    return SHA512_256_oid;
                                }
                            } else {
                                return SHA512_224_oid;
                            }
                        } else {
                            return SHA224_oid;
                        }
                    } else {
                        return SHA512_oid;
                    }
                } else {
                    return SHA384_oid;
                }
            } else {
                return SHA256_oid;
            }
        } else {
            return SHA_oid;
        }
    }

    private static ObjectIdentifier oid(int... values) {
        return ObjectIdentifier.newInternal(values);
    }

    private static Map<String, ObjectIdentifier> oidTable() throws IOException {
        Object tab;
        if ((tab = oidTable) == null) {
            Class var1 = AlgorithmId.class;
            synchronized(AlgorithmId.class) {
                if ((tab = oidTable) == null) {
                    oidTable = (Map)(tab = computeOidTable());
                }
            }
        }

        return (Map)tab;
    }

    private static HashMap<String, ObjectIdentifier> computeOidTable() throws IOException {
        HashMap<String, ObjectIdentifier> tab = new HashMap();
        Provider[] var1 = Security.getProviders();
        int var2 = var1.length;

        for(int var3 = 0; var3 < var2; ++var3) {
            Provider provider = var1[var3];
            Iterator var5 = provider.keySet().iterator();

            while(var5.hasNext()) {
                Object key = var5.next();
                String alias = (String)key;
                String upperCaseAlias = alias.toUpperCase(Locale.ENGLISH);
                int index;
                if (upperCaseAlias.startsWith("ALG.ALIAS") && (index = upperCaseAlias.indexOf("OID.", 0)) != -1) {
                    index += "OID.".length();
                    if (index == alias.length()) {
                        break;
                    }

                    String oidString = alias.substring(index);
                    String stdAlgName = provider.getProperty(alias);
                    if (stdAlgName != null) {
                        stdAlgName = stdAlgName.toUpperCase(Locale.ENGLISH);
                    }

                    if (stdAlgName != null && tab.get(stdAlgName) == null) {
                        tab.put(stdAlgName, new ObjectIdentifier(oidString));
                    }
                }
            }
        }

        return tab;
    }

    public static String makeSigAlg(String digAlg, String encAlg) {
        digAlg = digAlg.replace("-", "");
        if (encAlg.equalsIgnoreCase("EC")) {
            encAlg = "ECDSA";
        }

        return digAlg + "with" + encAlg;
    }

    public static String getEncAlgFromSigAlg(String signatureAlgorithm) {
        signatureAlgorithm = signatureAlgorithm.toUpperCase(Locale.ENGLISH);
        int with = signatureAlgorithm.indexOf("WITH");
        String keyAlgorithm = null;
        if (with > 0) {
            int and = signatureAlgorithm.indexOf("AND", with + 4);
            if (and > 0) {
                keyAlgorithm = signatureAlgorithm.substring(with + 4, and);
            } else {
                keyAlgorithm = signatureAlgorithm.substring(with + 4);
            }

            if (keyAlgorithm.equalsIgnoreCase("ECDSA")) {
                keyAlgorithm = "EC";
            }
        }

        return keyAlgorithm;
    }

    public static String getDigAlgFromSigAlg(String signatureAlgorithm) {
        signatureAlgorithm = signatureAlgorithm.toUpperCase(Locale.ENGLISH);
        int with = signatureAlgorithm.indexOf("WITH");
        return with > 0 ? signatureAlgorithm.substring(0, with) : null;
    }

    public static void checkKeyAndSigAlgMatch(String kAlg, String sAlg) {
        String sAlgUp = sAlg.toUpperCase(Locale.US);
        if (sAlgUp.endsWith("WITHRSA") && !kAlg.equalsIgnoreCase("RSA") || sAlgUp.endsWith("WITHECDSA") && !kAlg.equalsIgnoreCase("EC") || sAlgUp.endsWith("WITHDSA") && !kAlg.equalsIgnoreCase("DSA")) {
            throw new IllegalArgumentException("key algorithm not compatible with signature algorithm");
        }
    }

    public static String getDefaultSigAlgForKey(PrivateKey k) {
        String var1 = k.getAlgorithm().toUpperCase(Locale.ENGLISH);
        byte var2 = -1;
        switch(var1.hashCode()) {
        case 2206:
            if (var1.equals("EC")) {
                var2 = 0;
            }
            break;
        case 67986:
            if (var1.equals("DSA")) {
                var2 = 1;
            }
            break;
        case 81440:
            if (var1.equals("RSA")) {
                var2 = 2;
            }
            break;
        case 1775481508:
            if (var1.equals("RSASSA-PSS")) {
                var2 = 3;
            }
        }

        switch(var2) {
        case 0:
            return ecStrength(KeyUtil.getKeySize(k)) + "withECDSA";
        case 1:
            return ifcFfcStrength(KeyUtil.getKeySize(k)) + "withDSA";
        case 2:
            return ifcFfcStrength(KeyUtil.getKeySize(k)) + "withRSA";
        case 3:
            return "RSASSA-PSS";
        default:
            return null;
        }
    }

    public static AlgorithmId getWithParameterSpec(String algName, AlgorithmParameterSpec spec) throws NoSuchAlgorithmException {
        if (spec == null) {
            return get(algName);
        } else if (spec == AlgorithmId.PSSParamsHolder.PSS_256_SPEC) {
            return AlgorithmId.PSSParamsHolder.PSS_256_ID;
        } else if (spec == AlgorithmId.PSSParamsHolder.PSS_384_SPEC) {
            return AlgorithmId.PSSParamsHolder.PSS_384_ID;
        } else if (spec == AlgorithmId.PSSParamsHolder.PSS_512_SPEC) {
            return AlgorithmId.PSSParamsHolder.PSS_512_ID;
        } else {
            try {
                AlgorithmParameters result = AlgorithmParameters.getInstance(algName);
                result.init(spec);
                return get(result);
            } catch (NoSuchAlgorithmException | InvalidParameterSpecException var3) {
                throw new ProviderException(var3);
            }
        }
    }

    public static PSSParameterSpec getDefaultAlgorithmParameterSpec(String sigAlg, PrivateKey k) {
        if (sigAlg.equalsIgnoreCase("RSASSA-PSS")) {
            String var2 = ifcFfcStrength(KeyUtil.getKeySize(k));
            byte var3 = -1;
            switch(var2.hashCode()) {
            case -1850268089:
                if (var2.equals("SHA256")) {
                    var3 = 0;
                }
                break;
            case -1850267037:
                if (var2.equals("SHA384")) {
                    var3 = 1;
                }
                break;
            case -1850265334:
                if (var2.equals("SHA512")) {
                    var3 = 2;
                }
            }

            switch(var3) {
            case 0:
                return AlgorithmId.PSSParamsHolder.PSS_256_SPEC;
            case 1:
                return AlgorithmId.PSSParamsHolder.PSS_384_SPEC;
            case 2:
                return AlgorithmId.PSSParamsHolder.PSS_512_SPEC;
            default:
                throw new AssertionError("Should not happen");
            }
        } else {
            return null;
        }
    }

    private static String ecStrength(int bitLength) {
        if (bitLength >= 512) {
            return "SHA512";
        } else {
            return bitLength >= 384 ? "SHA384" : "SHA256";
        }
    }

    private static String ifcFfcStrength(int bitLength) {
        if (bitLength > 7680) {
            return "SHA512";
        } else {
            return bitLength > 3072 ? "SHA384" : "SHA256";
        }
    }

    static {
        DH_oid = ObjectIdentifier.newInternal(DH_data);
        DH_PKIX_oid = ObjectIdentifier.newInternal(DH_PKIX_data);
        DSA_OIW_oid = ObjectIdentifier.newInternal(DSA_OIW_data);
        DSA_oid = ObjectIdentifier.newInternal(DSA_PKIX_data);
        RSA_oid = ObjectIdentifier.newInternal(RSA_data);
        md2WithRSAEncryption_oid = ObjectIdentifier.newInternal(md2WithRSAEncryption_data);
        md5WithRSAEncryption_oid = ObjectIdentifier.newInternal(md5WithRSAEncryption_data);
        sha1WithRSAEncryption_oid = ObjectIdentifier.newInternal(sha1WithRSAEncryption_data);
        sha1WithRSAEncryption_OIW_oid = ObjectIdentifier.newInternal(sha1WithRSAEncryption_OIW_data);
        sha224WithRSAEncryption_oid = ObjectIdentifier.newInternal(sha224WithRSAEncryption_data);
        sha256WithRSAEncryption_oid = ObjectIdentifier.newInternal(sha256WithRSAEncryption_data);
        sha384WithRSAEncryption_oid = ObjectIdentifier.newInternal(sha384WithRSAEncryption_data);
        sha512WithRSAEncryption_oid = ObjectIdentifier.newInternal(sha512WithRSAEncryption_data);
        shaWithDSA_OIW_oid = ObjectIdentifier.newInternal(shaWithDSA_OIW_data);
        sha1WithDSA_OIW_oid = ObjectIdentifier.newInternal(sha1WithDSA_OIW_data);
        sha1WithDSA_oid = ObjectIdentifier.newInternal(dsaWithSHA1_PKIX_data);
        nameTable = new HashMap();
        nameTable.put(MD5_oid, "MD5");
        nameTable.put(MD2_oid, "MD2");
        nameTable.put(SHA_oid, "SHA-1");
        nameTable.put(SHA224_oid, "SHA-224");
        nameTable.put(SHA256_oid, "SHA-256");
        nameTable.put(SHA384_oid, "SHA-384");
        nameTable.put(SHA512_oid, "SHA-512");
        nameTable.put(SHA512_224_oid, "SHA-512/224");
        nameTable.put(SHA512_256_oid, "SHA-512/256");
        nameTable.put(RSAEncryption_oid, "RSA");
        nameTable.put(RSA_oid, "RSA");
        nameTable.put(DH_oid, "Diffie-Hellman");
        nameTable.put(DH_PKIX_oid, "Diffie-Hellman");
        nameTable.put(DSA_oid, "DSA");
        nameTable.put(DSA_OIW_oid, "DSA");
        nameTable.put(EC_oid, "EC");
        nameTable.put(ECDH_oid, "ECDH");
        nameTable.put(AES_oid, "AES");
        nameTable.put(sha1WithECDSA_oid, "SHA1withECDSA");
        nameTable.put(sha224WithECDSA_oid, "SHA224withECDSA");
        nameTable.put(sha256WithECDSA_oid, "SHA256withECDSA");
        nameTable.put(sha384WithECDSA_oid, "SHA384withECDSA");
        nameTable.put(sha512WithECDSA_oid, "SHA512withECDSA");
        nameTable.put(md5WithRSAEncryption_oid, "MD5withRSA");
        nameTable.put(md2WithRSAEncryption_oid, "MD2withRSA");
        nameTable.put(sha1WithDSA_oid, "SHA1withDSA");
        nameTable.put(sha1WithDSA_OIW_oid, "SHA1withDSA");
        nameTable.put(shaWithDSA_OIW_oid, "SHA1withDSA");
        nameTable.put(sha224WithDSA_oid, "SHA224withDSA");
        nameTable.put(sha256WithDSA_oid, "SHA256withDSA");
        nameTable.put(sha1WithRSAEncryption_oid, "SHA1withRSA");
        nameTable.put(sha1WithRSAEncryption_OIW_oid, "SHA1withRSA");
        nameTable.put(sha224WithRSAEncryption_oid, "SHA224withRSA");
        nameTable.put(sha256WithRSAEncryption_oid, "SHA256withRSA");
        nameTable.put(sha384WithRSAEncryption_oid, "SHA384withRSA");
        nameTable.put(sha512WithRSAEncryption_oid, "SHA512withRSA");
        nameTable.put(sha512_224WithRSAEncryption_oid, "SHA512/224withRSA");
        nameTable.put(sha512_256WithRSAEncryption_oid, "SHA512/256withRSA");
        nameTable.put(RSASSA_PSS_oid, "RSASSA-PSS");
        nameTable.put(RSAES_OAEP_oid, "RSAES-OAEP");
        nameTable.put(pbeWithMD5AndDES_oid, "PBEWithMD5AndDES");
        nameTable.put(pbeWithMD5AndRC2_oid, "PBEWithMD5AndRC2");
        nameTable.put(pbeWithSHA1AndDES_oid, "PBEWithSHA1AndDES");
        nameTable.put(pbeWithSHA1AndRC2_oid, "PBEWithSHA1AndRC2");
        nameTable.put(pbeWithSHA1AndDESede_oid, "PBEWithSHA1AndDESede");
        nameTable.put(pbeWithSHA1AndRC2_40_oid, "PBEWithSHA1AndRC2_40");
    }

    private static class PSSParamsHolder {
        static final PSSParameterSpec PSS_256_SPEC = new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 32, 1);
        static final PSSParameterSpec PSS_384_SPEC = new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 48, 1);
        static final PSSParameterSpec PSS_512_SPEC = new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 64, 1);
        static final AlgorithmId PSS_256_ID;
        static final AlgorithmId PSS_384_ID;
        static final AlgorithmId PSS_512_ID;

        private PSSParamsHolder() {
        }

        static {
            try {
                PSS_256_ID = new AlgorithmId(AlgorithmId.RSASSA_PSS_oid, new DerValue(PSSParameters.getEncoded(PSS_256_SPEC)));
                PSS_384_ID = new AlgorithmId(AlgorithmId.RSASSA_PSS_oid, new DerValue(PSSParameters.getEncoded(PSS_384_SPEC)));
                PSS_512_ID = new AlgorithmId(AlgorithmId.RSASSA_PSS_oid, new DerValue(PSSParameters.getEncoded(PSS_512_SPEC)));
            } catch (IOException var1) {
                throw new AssertionError("Should not happen", var1);
            }
        }
    }
}
