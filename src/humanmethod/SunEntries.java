package humanmethod;

import humanmethod.NativePRNG.Blocking;
import humanmethod.NativePRNG.NonBlocking;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.Provider.Service;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;

public final class SunEntries {
    public static final String DEF_SECURE_RANDOM_ALGO;
    private LinkedHashSet<Service> services = new LinkedHashSet(50, 0.9F);
    private static final String PROP_EGD = "java.security.egd";
    private static final String PROP_RNDSOURCE = "securerandom.source";
    private static final boolean useLegacyDSA = Boolean.parseBoolean(GetPropertyAction.privilegedGetProperty("jdk.security.legacyDSAKeyPairGenerator"));
    static final String URL_DEV_RANDOM = "file:/dev/random";
    static final String URL_DEV_URANDOM = "file:/dev/urandom";
    private static final String seedSource = (String)AccessController.doPrivileged(new PrivilegedAction<String>() {
        public String run() {
            String egdSource = System.getProperty("java.security.egd", "");
            if (egdSource.length() != 0) {
                return egdSource;
            } else {
                egdSource = Security.getProperty("securerandom.source");
                return egdSource == null ? "" : egdSource;
            }
        }
    });

    public static List<String> createAliases(String... aliases) {
        return Arrays.asList(aliases);
    }

    public static List<String> createAliasesWithOid(String... oids) {
        String[] result = (String[])Arrays.copyOf(oids, oids.length + 1);
        result[result.length - 1] = "OID." + oids[0];
        return Arrays.asList(result);
    }

    SunEntries(Provider p) {
        HashMap<String, String> attrs = new HashMap(3);
        attrs.put("ThreadSafe", "true");
        if (NativePRNG.isAvailable()) {
            this.add(p, "SecureRandom", "NativePRNG", "sun.security.provider.NativePRNG", (List)null, attrs);
        }

        if (Blocking.isAvailable()) {
            this.add(p, "SecureRandom", "NativePRNGBlocking", "sun.security.provider.NativePRNG$Blocking", (List)null, attrs);
        }

        if (NonBlocking.isAvailable()) {
            this.add(p, "SecureRandom", "NativePRNGNonBlocking", "sun.security.provider.NativePRNG$NonBlocking", (List)null, attrs);
        }

        attrs.put("ImplementedIn", "Software");
        this.add(p, "SecureRandom", "DRBG", "sun.security.provider.DRBG", (List)null, attrs);
        this.add(p, "SecureRandom", "SHA1PRNG", "sun.security.provider.SecureRandom", (List)null, attrs);
        attrs.clear();
        String dsaKeyClasses = "java.security.interfaces.DSAPublicKey|java.security.interfaces.DSAPrivateKey";
        attrs.put("SupportedKeyClasses", dsaKeyClasses);
        attrs.put("ImplementedIn", "Software");
        attrs.put("KeySize", "1024");
        this.add(p, "Signature", "SHA1withDSA", "sun.security.provider.DSA$SHA1withDSA", createAliasesWithOid("1.2.840.10040.4.3", "DSA", "DSS", "SHA/DSA", "SHA-1/DSA", "SHA1/DSA", "SHAwithDSA", "DSAWithSHA1", "1.3.14.3.2.13", "1.3.14.3.2.27"), attrs);
        this.add(p, "Signature", "NONEwithDSA", "sun.security.provider.DSA$RawDSA", createAliases("RawDSA"), attrs);
        attrs.put("KeySize", "2048");
        this.add(p, "Signature", "SHA224withDSA", "sun.security.provider.DSA$SHA224withDSA", createAliasesWithOid("2.16.840.1.101.3.4.3.1"), attrs);
        this.add(p, "Signature", "SHA256withDSA", "sun.security.provider.DSA$SHA256withDSA", createAliasesWithOid("2.16.840.1.101.3.4.3.2"), attrs);
        attrs.remove("KeySize");
        this.add(p, "Signature", "SHA1withDSAinP1363Format", "sun.security.provider.DSA$SHA1withDSAinP1363Format", (List)null, (HashMap)null);
        this.add(p, "Signature", "NONEwithDSAinP1363Format", "sun.security.provider.DSA$RawDSAinP1363Format", (List)null, (HashMap)null);
        this.add(p, "Signature", "SHA224withDSAinP1363Format", "sun.security.provider.DSA$SHA224withDSAinP1363Format", (List)null, (HashMap)null);
        this.add(p, "Signature", "SHA256withDSAinP1363Format", "sun.security.provider.DSA$SHA256withDSAinP1363Format", (List)null, (HashMap)null);
        attrs.clear();
        attrs.put("ImplementedIn", "Software");
        attrs.put("KeySize", "2048");
        String dsaOid = "1.2.840.10040.4.1";
        List<String> dsaAliases = createAliasesWithOid(dsaOid, "1.3.14.3.2.12");
        String dsaKPGImplClass = "sun.security.provider.DSAKeyPairGenerator$";
        dsaKPGImplClass = dsaKPGImplClass + (useLegacyDSA ? "Legacy" : "Current");
        this.add(p, "KeyPairGenerator", "DSA", dsaKPGImplClass, dsaAliases, attrs);
        this.add(p, "AlgorithmParameterGenerator", "DSA", "sun.security.provider.DSAParameterGenerator", dsaAliases, attrs);
        attrs.remove("KeySize");
        this.add(p, "AlgorithmParameters", "DSA", "sun.security.provider.DSAParameters", dsaAliases, attrs);
        this.add(p, "KeyFactory", "DSA", "sun.security.provider.DSAKeyFactory", dsaAliases, attrs);
        this.add(p, "MessageDigest", "MD2", "sun.security.provider.MD2", (List)null, attrs);
        this.add(p, "MessageDigest", "MD5", "sun.security.provider.MD5", (List)null, attrs);
        this.add(p, "MessageDigest", "SHA", "sun.security.provider.SHA", createAliasesWithOid("1.3.14.3.2.26", "SHA-1", "SHA1"), attrs);
        String sha2BaseOid = "2.16.840.1.101.3.4.2";
        this.add(p, "MessageDigest", "SHA-224", "sun.security.provider.SHA2$SHA224", createAliasesWithOid(sha2BaseOid + ".4"), attrs);
        this.add(p, "MessageDigest", "SHA-256", "sun.security.provider.SHA2$SHA256", createAliasesWithOid(sha2BaseOid + ".1"), attrs);
        this.add(p, "MessageDigest", "SHA-384", "sun.security.provider.SHA5$SHA384", createAliasesWithOid(sha2BaseOid + ".2"), attrs);
        this.add(p, "MessageDigest", "SHA-512", "sun.security.provider.SHA5$SHA512", createAliasesWithOid(sha2BaseOid + ".3"), attrs);
        this.add(p, "MessageDigest", "SHA-512/224", "sun.security.provider.SHA5$SHA512_224", createAliasesWithOid(sha2BaseOid + ".5"), attrs);
        this.add(p, "MessageDigest", "SHA-512/256", "sun.security.provider.SHA5$SHA512_256", createAliasesWithOid(sha2BaseOid + ".6"), attrs);
        this.add(p, "MessageDigest", "SHA3-224", "sun.security.provider.SHA3$SHA224", createAliasesWithOid(sha2BaseOid + ".7"), attrs);
        this.add(p, "MessageDigest", "SHA3-256", "sun.security.provider.SHA3$SHA256", createAliasesWithOid(sha2BaseOid + ".8"), attrs);
        this.add(p, "MessageDigest", "SHA3-384", "sun.security.provider.SHA3$SHA384", createAliasesWithOid(sha2BaseOid + ".9"), attrs);
        this.add(p, "MessageDigest", "SHA3-512", "sun.security.provider.SHA3$SHA512", createAliasesWithOid(sha2BaseOid + ".10"), attrs);
        this.add(p, "CertificateFactory", "X.509", "sun.security.provider.X509Factory", createAliases("X509"), attrs);
        this.add(p, "KeyStore", "PKCS12", "sun.security.pkcs12.PKCS12KeyStore$DualFormatPKCS12", (List)null, (HashMap)null);
        this.add(p, "KeyStore", "JKS", "sun.security.provider.JavaKeyStore$DualFormatJKS", (List)null, attrs);
        this.add(p, "KeyStore", "CaseExactJKS", "sun.security.provider.JavaKeyStore$CaseExactJKS", (List)null, attrs);
        this.add(p, "KeyStore", "DKS", "sun.security.provider.DomainKeyStore$DKS", (List)null, attrs);
        this.add(p, "CertStore", "Collection", "sun.security.provider.certpath.CollectionCertStore", (List)null, attrs);
        this.add(p, "CertStore", "com.sun.security.IndexedCollection", "sun.security.provider.certpath.IndexedCollectionCertStore", (List)null, attrs);
        this.add(p, "Policy", "JavaPolicy", "sun.security.provider.PolicySpiFile", (List)null, (HashMap)null);
        this.add(p, "Configuration", "JavaLoginConfig", "sun.security.provider.ConfigFile$Spi", (List)null, (HashMap)null);
        attrs.clear();
        attrs.put("ValidationAlgorithm", "RFC5280");
        attrs.put("ImplementedIn", "Software");
        this.add(p, "CertPathBuilder", "PKIX", "sun.security.provider.certpath.SunCertPathBuilder", (List)null, attrs);
        this.add(p, "CertPathValidator", "PKIX", "sun.security.provider.certpath.PKIXCertPathValidator", (List)null, attrs);
    }

    Iterator<Service> iterator() {
        return this.services.iterator();
    }

    private void add(Provider p, String type, String algo, String cn, List<String> aliases, HashMap<String, String> attrs) {
        this.services.add(new Service(p, type, algo, cn, aliases, attrs));
    }

    static String getSeedSource() {
        return seedSource;
    }

    static File getDeviceFile(URL device) throws IOException {
        try {
            URI deviceURI = device.toURI();
            if (deviceURI.isOpaque()) {
                URI localDir = (new File(StaticProperty.userDir())).toURI();
                String uriPath = localDir.toString() + deviceURI.toString().substring(5);
                return new File(URI.create(uriPath));
            } else {
                return new File(deviceURI);
            }
        } catch (URISyntaxException var4) {
            return new File(device.getPath());
        }
    }

    static {
        DEF_SECURE_RANDOM_ALGO = !NativePRNG.isAvailable() || !seedSource.equals("file:/dev/urandom") && !seedSource.equals("file:/dev/random") ? "DRBG" : "NativePRNG";
    }
}