package humanmethod;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.AlgorithmParametersSpi;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;

public final class ECParameters extends AlgorithmParametersSpi {
    private NamedCurve namedCurve;

    public static AlgorithmParameters getAlgorithmParameters(ECParameterSpec spec) throws InvalidKeyException {
        try {
            AlgorithmParameters params = AlgorithmParameters.getInstance("EC", "SunEC");
            params.init(spec);
            return params;
        } catch (GeneralSecurityException var2) {
            throw new InvalidKeyException("EC parameters error", var2);
        }
    }

    public ECParameters() {
    }

    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec == null) {
            throw new InvalidParameterSpecException("paramSpec must not be null");
        } else if (paramSpec instanceof NamedCurve) {
            this.namedCurve = (NamedCurve)paramSpec;
        } else {
            if (paramSpec instanceof ECParameterSpec) {
                this.namedCurve = CurveDB.lookup((ECParameterSpec)paramSpec);
            } else if (paramSpec instanceof ECGenParameterSpec) {
                String name = ((ECGenParameterSpec)paramSpec).getName();
                this.namedCurve = CurveDB.lookup(name);
            } else {
                if (!(paramSpec instanceof ECKeySizeParameterSpec)) {
                    throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
                }

                int keySize = ((ECKeySizeParameterSpec)paramSpec).getKeySize();
                this.namedCurve = CurveDB.lookup(keySize);
            }

            if (this.namedCurve == null) {
                throw new InvalidParameterSpecException("Not a supported curve: " + paramSpec);
            }
        }
    }

    protected void engineInit(byte[] params) throws IOException {
        DerValue encodedParams = new DerValue(params);
        if (encodedParams.tag == 6) {
            ObjectIdentifier oid = encodedParams.getOID();
            NamedCurve spec = CurveDB.lookup(oid.toString());
            if (spec == null) {
                throw new IOException("Unknown named curve: " + oid);
            } else {
                this.namedCurve = spec;
            }
        } else {
            throw new IOException("Only named ECParameters supported");
        }
    }

    protected void engineInit(byte[] params, String decodingMethod) throws IOException {
        this.engineInit(params);
    }

    //Attenzione aggiunto CAST a T quando era solo AlgorithmParameterSpec
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> spec) throws InvalidParameterSpecException {
        if (spec.isAssignableFrom(ECParameterSpec.class)) {
            return (T)(AlgorithmParameterSpec)spec.cast(this.namedCurve);
        } else if (spec.isAssignableFrom(ECGenParameterSpec.class)) {
            String name = this.namedCurve.getObjectId();
            return (T)(AlgorithmParameterSpec)spec.cast(new ECGenParameterSpec(name));
        } else if (spec.isAssignableFrom(ECKeySizeParameterSpec.class)) {
            int keySize = this.namedCurve.getCurve().getField().getFieldSize();
            return (T)(AlgorithmParameterSpec)spec.cast(new ECKeySizeParameterSpec(keySize));
        } else {
            throw new InvalidParameterSpecException("Only ECParameterSpec and ECGenParameterSpec supported");
        }
    }

    protected byte[] engineGetEncoded() throws IOException {
        return this.namedCurve.getEncoded();
    }

    protected byte[] engineGetEncoded(String encodingMethod) throws IOException {
        return this.engineGetEncoded();
    }

    protected String engineToString() {
        return this.namedCurve == null ? "Not initialized" : this.namedCurve.toString();
    }
}