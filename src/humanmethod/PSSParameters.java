package humanmethod;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

public final class PSSParameters extends AlgorithmParametersSpi {
    private PSSParameterSpec spec;

    public PSSParameters() {
    }

    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof PSSParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        } else {
            PSSParameterSpec spec = (PSSParameterSpec)paramSpec;
            String mgfName = spec.getMGFAlgorithm();
            if (!spec.getMGFAlgorithm().equalsIgnoreCase("MGF1")) {
                throw new InvalidParameterSpecException("Unsupported mgf " + mgfName + "; MGF1 only");
            } else {
                AlgorithmParameterSpec mgfSpec = spec.getMGFParameters();
                if (!(mgfSpec instanceof MGF1ParameterSpec)) {
                    throw new InvalidParameterSpecException("Inappropriate mgf parameters; non-null MGF1ParameterSpec only");
                } else {
                    this.spec = spec;
                }
            }
        }
    }

    protected void engineInit(byte[] encoded) throws IOException {
        String mdName = PSSParameterSpec.DEFAULT.getDigestAlgorithm();
        MGF1ParameterSpec mgfSpec = (MGF1ParameterSpec)PSSParameterSpec.DEFAULT.getMGFParameters();
        int saltLength = PSSParameterSpec.DEFAULT.getSaltLength();
        int trailerField = PSSParameterSpec.DEFAULT.getTrailerField();
        DerInputStream der = new DerInputStream(encoded);
        DerValue[] datum = der.getSequence(4);
        DerValue[] var8 = datum;
        int var9 = datum.length;

        for(int var10 = 0; var10 < var9; ++var10) {
            DerValue d = var8[var10];
            if (d.isContextSpecific((byte)0)) {
                mdName = AlgorithmId.parse(d.data.getDerValue()).getName();
            } else if (d.isContextSpecific((byte)1)) {
                AlgorithmId val = AlgorithmId.parse(d.data.getDerValue());
                if (!val.getOID().equals(AlgorithmId.mgf1_oid)) {
                    throw new IOException("Only MGF1 mgf is supported");
                }

                AlgorithmId params = AlgorithmId.parse(new DerValue(val.getEncodedParams()));
                String mgfDigestName = params.getName();
                byte var16 = -1;
                switch(mgfDigestName.hashCode()) {
                case -1523887821:
                    if (mgfDigestName.equals("SHA-224")) {
                        var16 = 1;
                    }
                    break;
                case -1523887726:
                    if (mgfDigestName.equals("SHA-256")) {
                        var16 = 2;
                    }
                    break;
                case -1523886674:
                    if (mgfDigestName.equals("SHA-384")) {
                        var16 = 3;
                    }
                    break;
                case -1523884971:
                    if (mgfDigestName.equals("SHA-512")) {
                        var16 = 4;
                    }
                    break;
                case 78861104:
                    if (mgfDigestName.equals("SHA-1")) {
                        var16 = 0;
                    }
                    break;
                case 752961850:
                    if (mgfDigestName.equals("SHA-512/224")) {
                        var16 = 5;
                    }
                    break;
                case 752961945:
                    if (mgfDigestName.equals("SHA-512/256")) {
                        var16 = 6;
                    }
                }

                switch(var16) {
                case 0:
                    mgfSpec = MGF1ParameterSpec.SHA1;
                    break;
                case 1:
                    mgfSpec = MGF1ParameterSpec.SHA224;
                    break;
                case 2:
                    mgfSpec = MGF1ParameterSpec.SHA256;
                    break;
                case 3:
                    mgfSpec = MGF1ParameterSpec.SHA384;
                    break;
                case 4:
                    mgfSpec = MGF1ParameterSpec.SHA512;
                    break;
                case 5:
                    mgfSpec = MGF1ParameterSpec.SHA512_224;
                    break;
                case 6:
                    mgfSpec = MGF1ParameterSpec.SHA512_256;
                    break;
                default:
                    throw new IOException("Unrecognized message digest algorithm " + mgfDigestName);
                }
            } else if (d.isContextSpecific((byte)2)) {
                saltLength = d.data.getDerValue().getInteger();
                if (saltLength < 0) {
                    throw new IOException("Negative value for saltLength");
                }
            } else {
                if (!d.isContextSpecific((byte)3)) {
                    throw new IOException("Invalid encoded PSSParameters");
                }

                trailerField = d.data.getDerValue().getInteger();
                if (trailerField != 1) {
                    throw new IOException("Unsupported trailerField value " + trailerField);
                }
            }
        }

        this.spec = new PSSParameterSpec(mdName, "MGF1", mgfSpec, saltLength, trailerField);
    }

    protected void engineInit(byte[] encoded, String decodingMethod) throws IOException {
        if (decodingMethod != null && !decodingMethod.equalsIgnoreCase("ASN.1")) {
            throw new IllegalArgumentException("Only support ASN.1 format");
        } else {
            this.engineInit(encoded);
        }
    }
    
    //Attenzione aggiunto CAST a T quando era solo AlgorithmParameterSpec
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (PSSParameterSpec.class.isAssignableFrom(paramSpec)) {
            return (T)(AlgorithmParameterSpec)paramSpec.cast(this.spec);
        } else {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        return getEncoded(this.spec);
    }

    protected byte[] engineGetEncoded(String encMethod) throws IOException {
        if (encMethod != null && !encMethod.equalsIgnoreCase("ASN.1")) {
            throw new IllegalArgumentException("Only support ASN.1 format");
        } else {
            return this.engineGetEncoded();
        }
    }

    protected String engineToString() {
        return this.spec.toString();
    }

    public static byte[] getEncoded(PSSParameterSpec spec) throws IOException {
        AlgorithmParameterSpec mgfSpec = spec.getMGFParameters();
        if (!(mgfSpec instanceof MGF1ParameterSpec)) {
            throw new IOException("Cannot encode " + mgfSpec);
        } else {
            MGF1ParameterSpec mgf1Spec = (MGF1ParameterSpec)mgfSpec;
            DerOutputStream tmp = new DerOutputStream();

            AlgorithmId mdAlgId;
            try {
                mdAlgId = AlgorithmId.get(spec.getDigestAlgorithm());
            } catch (NoSuchAlgorithmException var10) {
                throw new IOException("AlgorithmId " + spec.getDigestAlgorithm() + " impl not found");
            }

            DerOutputStream tmp2;
            if (!mdAlgId.getOID().equals(AlgorithmId.SHA_oid)) {
                tmp2 = new DerOutputStream();
                mdAlgId.derEncode(tmp2);
                tmp.write(DerValue.createTag((byte)-128, true, (byte)0), tmp2);
            }

            AlgorithmId mgfDigestId;
            try {
                mgfDigestId = AlgorithmId.get(mgf1Spec.getDigestAlgorithm());
            } catch (NoSuchAlgorithmException var9) {
                throw new IOException("AlgorithmId " + mgf1Spec.getDigestAlgorithm() + " impl not found");
            }

            if (!mgfDigestId.getOID().equals(AlgorithmId.SHA_oid)) {
                tmp2 = new DerOutputStream();
                tmp2.putOID(AlgorithmId.mgf1_oid);
                mgfDigestId.encode(tmp2);
                DerOutputStream tmp3 = new DerOutputStream();
                tmp3.write((byte)48, tmp2);
                tmp.write(DerValue.createTag((byte)-128, true, (byte)1), tmp3);
            }

            if (spec.getSaltLength() != 20) {
                tmp2 = new DerOutputStream();
                tmp2.putInteger(spec.getSaltLength());
                tmp.write(DerValue.createTag((byte)-128, true, (byte)2), tmp2);
            }

            if (spec.getTrailerField() != 1) {
                tmp2 = new DerOutputStream();
                tmp2.putInteger(spec.getTrailerField());
                tmp.write(DerValue.createTag((byte)-128, true, (byte)3), tmp2);
            }

            DerOutputStream out = new DerOutputStream();
            out.write((byte)48, tmp);
            return out.toByteArray();
        }
    }
}
