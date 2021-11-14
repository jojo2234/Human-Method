package humanmethod;

import humanmethod.CurveDB;
import humanmethod.ECDSASignature.Raw;
import humanmethod.ECDSASignature.RawinP1363Format;
import humanmethod.ECDSASignature.SHA1;
import humanmethod.ECDSASignature.SHA1inP1363Format;
import humanmethod.ECDSASignature.SHA224;
import humanmethod.ECDSASignature.SHA224inP1363Format;
import humanmethod.ECDSASignature.SHA256;
import humanmethod.ECDSASignature.SHA256inP1363Format;
import humanmethod.ECDSASignature.SHA384;
import humanmethod.ECDSASignature.SHA384inP1363Format;
import humanmethod.ECDSASignature.SHA512;
import humanmethod.ECDSASignature.SHA512inP1363Format;
import humanmethod.ECKeyFactory;
import humanmethod.NamedCurve;
import humanmethod.SecurityConstants;
import java.security.AccessController;
import java.security.InvalidParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Provider.Service;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

public final class SunEC extends Provider {
    private static final long serialVersionUID = -2279741672933606418L;
    private static boolean useFullImplementation = true;

    public SunEC() {
        super("SunEC", GetPropertyAction.privilegedGetProperty("java.specification.version"), "Sun Elliptic Curve provider (EC, ECDSA, ECDH)");
        AccessController.doPrivileged((PrivilegedAction<Void>) () -> {
            SunEC.this.putEntries(SunEC.useFullImplementation);
            return null;
        });
    }

    void putEntries(boolean useFullImplementation) {
        HashMap<String, String> ATTRS = new HashMap(3);
        ATTRS.put("ImplementedIn", "Software");
        String ecKeyClasses = "java.security.interfaces.ECPublicKey|java.security.interfaces.ECPrivateKey";
        ATTRS.put("SupportedKeyClasses", ecKeyClasses);
        ATTRS.put("KeySize", "256");
        this.putService(new SunEC.ProviderService(this, "KeyFactory", "EC", "sun.security.ec.ECKeyFactory", new String[]{"EllipticCurve"}, ATTRS));
        boolean firstCurve = true;
        StringBuilder names = new StringBuilder();
        Pattern nameSplitPattern = Pattern.compile(",|\\[|\\]");
        Collection<? extends NamedCurve> supportedCurves = CurveDB.getSupportedCurves();
        Iterator var8 = supportedCurves.iterator();

        while(var8.hasNext()) {
            NamedCurve namedCurve = (NamedCurve)var8.next();
            if (!firstCurve) {
                names.append("|");
            } else {
                firstCurve = false;
            }

            names.append("[");
            String[] commonNames = nameSplitPattern.split(namedCurve.getName());
            String[] var11 = commonNames;
            int var12 = commonNames.length;

            for(int var13 = 0; var13 < var12; ++var13) {
                String commonName = var11[var13];
                names.append(commonName.trim());
                names.append(",");
            }

            names.append(namedCurve.getObjectId());
            names.append("]");
        }

        HashMap<String, String> apAttrs = new HashMap(ATTRS);
        apAttrs.put("SupportedCurves", names.toString());
        this.putService(new SunEC.ProviderService(this, "AlgorithmParameters", "EC", "sun.security.util.ECParameters", new String[]{"EllipticCurve", "1.2.840.10045.2.1", "OID.1.2.840.10045.2.1"}, apAttrs));
        this.putXDHEntries();
        if (useFullImplementation) {
            this.putService(new SunEC.ProviderService(this, "Signature", "NONEwithECDSA", "sun.security.ec.ECDSASignature$Raw", (String[])null, ATTRS));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA1withECDSA", "sun.security.ec.ECDSASignature$SHA1", new String[]{"1.2.840.10045.4.1", "OID.1.2.840.10045.4.1"}, ATTRS));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA224withECDSA", "sun.security.ec.ECDSASignature$SHA224", new String[]{"1.2.840.10045.4.3.1", "OID.1.2.840.10045.4.3.1"}, ATTRS));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA256withECDSA", "sun.security.ec.ECDSASignature$SHA256", new String[]{"1.2.840.10045.4.3.2", "OID.1.2.840.10045.4.3.2"}, ATTRS));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA384withECDSA", "sun.security.ec.ECDSASignature$SHA384", new String[]{"1.2.840.10045.4.3.3", "OID.1.2.840.10045.4.3.3"}, ATTRS));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA512withECDSA", "sun.security.ec.ECDSASignature$SHA512", new String[]{"1.2.840.10045.4.3.4", "OID.1.2.840.10045.4.3.4"}, ATTRS));
            this.putService(new SunEC.ProviderService(this, "Signature", "NONEwithECDSAinP1363Format", "sun.security.ec.ECDSASignature$RawinP1363Format"));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA1withECDSAinP1363Format", "sun.security.ec.ECDSASignature$SHA1inP1363Format"));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA224withECDSAinP1363Format", "sun.security.ec.ECDSASignature$SHA224inP1363Format"));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA256withECDSAinP1363Format", "sun.security.ec.ECDSASignature$SHA256inP1363Format"));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA384withECDSAinP1363Format", "sun.security.ec.ECDSASignature$SHA384inP1363Format"));
            this.putService(new SunEC.ProviderService(this, "Signature", "SHA512withECDSAinP1363Format", "sun.security.ec.ECDSASignature$SHA512inP1363Format"));
            this.putService(new SunEC.ProviderService(this, "KeyPairGenerator", "EC", "sun.security.ec.ECKeyPairGenerator", new String[]{"EllipticCurve"}, ATTRS));
            this.putService(new SunEC.ProviderService(this, "KeyAgreement", "ECDH", "sun.security.ec.ECDHKeyAgreement", (String[])null, ATTRS));
        }
    }

    private void putXDHEntries() {
        HashMap<String, String> ATTRS = new HashMap(1);
        ATTRS.put("ImplementedIn", "Software");
        this.putService(new SunEC.ProviderService(this, "KeyFactory", "XDH", "sun.security.ec.XDHKeyFactory", (String[])null, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyFactory", "X25519", "sun.security.ec.XDHKeyFactory.X25519", new String[]{"1.3.101.110", "OID.1.3.101.110"}, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyFactory", "X448", "sun.security.ec.XDHKeyFactory.X448", new String[]{"1.3.101.111", "OID.1.3.101.111"}, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyPairGenerator", "XDH", "sun.security.ec.XDHKeyPairGenerator", (String[])null, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyPairGenerator", "X25519", "sun.security.ec.XDHKeyPairGenerator.X25519", new String[]{"1.3.101.110", "OID.1.3.101.110"}, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyPairGenerator", "X448", "sun.security.ec.XDHKeyPairGenerator.X448", new String[]{"1.3.101.111", "OID.1.3.101.111"}, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyAgreement", "XDH", "sun.security.ec.XDHKeyAgreement", (String[])null, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyAgreement", "X25519", "sun.security.ec.XDHKeyAgreement.X25519", new String[]{"1.3.101.110", "OID.1.3.101.110"}, ATTRS));
        this.putService(new SunEC.ProviderService(this, "KeyAgreement", "X448", "sun.security.ec.XDHKeyAgreement.X448", new String[]{"1.3.101.111", "OID.1.3.101.111"}, ATTRS));
    }

    static {
        try {
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                public Void run() {
                    System.loadLibrary("sunec");
                    return null;
                }
            });
        } catch (UnsatisfiedLinkError var1) {
            useFullImplementation = false;
        }

    }

    private static class ProviderService extends Service {
        ProviderService(Provider p, String type, String algo, String cn) {
            super(p, type, algo, cn, (List)null, (Map)null);
        }

        ProviderService(Provider p, String type, String algo, String cn, String[] aliases, HashMap<String, String> attrs) {
            super(p, type, algo, cn, aliases == null ? null : Arrays.asList(aliases), attrs);
        }

        public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException {
            String type = this.getType();
            if (ctrParamObj != null) {
                throw new InvalidParameterException("constructorParameter not used with " + type + " engines");
            } else {
                String algo = this.getAlgorithm();

                try {
                    if (type.equals("Signature")) {
                        boolean inP1363 = algo.endsWith("inP1363Format");
                        if (inP1363) {
                            algo = algo.substring(0, algo.length() - 13);
                        }

                        if (algo.equals("SHA1withECDSA")) {
                            return inP1363 ? new SHA1inP1363Format() : new SHA1();
                        }

                        if (algo.equals("SHA224withECDSA")) {
                            return inP1363 ? new SHA224inP1363Format() : new SHA224();
                        }

                        if (algo.equals("SHA256withECDSA")) {
                            return inP1363 ? new SHA256inP1363Format() : new SHA256();
                        }

                        if (algo.equals("SHA384withECDSA")) {
                            return inP1363 ? new SHA384inP1363Format() : new SHA384();
                        }

                        if (algo.equals("SHA512withECDSA")) {
                            return inP1363 ? new SHA512inP1363Format() : new SHA512();
                        }

                        if (algo.equals("NONEwithECDSA")) {
                            return inP1363 ? new RawinP1363Format() : new Raw();
                        }
                    } else if (type.equals("KeyFactory")) {
                        if (algo.equals("EC")) {
                            return new ECKeyFactory();
                        }
                        /**
                        if (algo.equals("XDH")) {
                            return new XDHKeyFactory();
                        }

                        if (algo.equals("X25519")) {
                            return new X25519();
                        }

                        if (algo.equals("X448")) {
                            return new X448();
                        }*/
                    } else if (type.equals("AlgorithmParameters")) {
                        if (algo.equals("EC")) {
                            return new ECParameters();
                        }
                    } else if (type.equals("KeyPairGenerator")) {
                        /**
                        if (algo.equals("EC")) {
                            return new ECKeyPairGenerator();
                        }

                        if (algo.equals("XDH")) {
                            return new XDHKeyPairGenerator();
                        }

                        if (algo.equals("X25519")) {
                            return new sun.security.ec.XDHKeyPairGenerator.X25519();
                        }

                        if (algo.equals("X448")) {
                            return new sun.security.ec.XDHKeyPairGenerator.X448();
                        }
                        */
                    } else if (type.equals("KeyAgreement")) {
                        /**
                        if (algo.equals("ECDH")) {
                            return new ECDHKeyAgreement();
                        }

                        if (algo.equals("XDH")) {
                            return new XDHKeyAgreement();
                        }

                        if (algo.equals("X25519")) {
                            return new sun.security.ec.XDHKeyAgreement.X25519();
                        }

                        if (algo.equals("X448")) {
                            return new sun.security.ec.XDHKeyAgreement.X448();
                        }
                        * **/
                    }
                } catch (Exception var5) {
                    throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + " using SunEC", var5);
                }

                throw new ProviderException("No impl for " + algo + " " + type);
            }
        }
    }
}