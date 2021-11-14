package humanmethod;

import java.security.Provider;
import java.security.Provider.Service;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashSet;
import java.util.List;

public final class SunRsaSignEntries {
    private LinkedHashSet<Service> services = new LinkedHashSet(20, 0.9F);

    private void add(Provider p, String type, String algo, String cn, List<String> aliases, HashMap<String, String> attrs) {
        this.services.add(new Service(p, type, algo, cn, aliases, attrs));
    }

    public SunRsaSignEntries(Provider p) {
        String rsaOid = "1.2.840.113549.1.1";
        List<String> rsaAliases = SunEntries.createAliasesWithOid(rsaOid);
        List<String> rsapssAliases = SunEntries.createAliasesWithOid(rsaOid + ".10");
        String sha1withRSAOid2 = "1.3.14.3.2.29";
        HashMap<String, String> attrs = new HashMap(3);
        attrs.put("SupportedKeyClasses", "java.security.interfaces.RSAPublicKey|java.security.interfaces.RSAPrivateKey");
        this.add(p, "KeyFactory", "RSA", "sun.security.rsa.RSAKeyFactory$Legacy", rsaAliases, (HashMap)null);
        this.add(p, "KeyPairGenerator", "RSA", "sun.security.rsa.RSAKeyPairGenerator$Legacy", rsaAliases, (HashMap)null);
        this.add(p, "Signature", "MD2withRSA", "sun.security.rsa.RSASignature$MD2withRSA", SunEntries.createAliasesWithOid(rsaOid + ".2"), attrs);
        this.add(p, "Signature", "MD5withRSA", "sun.security.rsa.RSASignature$MD5withRSA", SunEntries.createAliasesWithOid(rsaOid + ".4"), attrs);
        this.add(p, "Signature", "SHA1withRSA", "sun.security.rsa.RSASignature$SHA1withRSA", SunEntries.createAliasesWithOid(rsaOid + ".5", sha1withRSAOid2), attrs);
        this.add(p, "Signature", "SHA224withRSA", "sun.security.rsa.RSASignature$SHA224withRSA", SunEntries.createAliasesWithOid(rsaOid + ".14"), attrs);
        this.add(p, "Signature", "SHA256withRSA", "sun.security.rsa.RSASignature$SHA256withRSA", SunEntries.createAliasesWithOid(rsaOid + ".11"), attrs);
        this.add(p, "Signature", "SHA384withRSA", "sun.security.rsa.RSASignature$SHA384withRSA", SunEntries.createAliasesWithOid(rsaOid + ".12"), attrs);
        this.add(p, "Signature", "SHA512withRSA", "sun.security.rsa.RSASignature$SHA512withRSA", SunEntries.createAliasesWithOid(rsaOid + ".13"), attrs);
        this.add(p, "Signature", "SHA512/224withRSA", "sun.security.rsa.RSASignature$SHA512_224withRSA", SunEntries.createAliasesWithOid(rsaOid + ".15"), attrs);
        this.add(p, "Signature", "SHA512/256withRSA", "sun.security.rsa.RSASignature$SHA512_256withRSA", SunEntries.createAliasesWithOid(rsaOid + ".16"), attrs);
        this.add(p, "KeyFactory", "RSASSA-PSS", "sun.security.rsa.RSAKeyFactory$PSS", rsapssAliases, (HashMap)null);
        this.add(p, "KeyPairGenerator", "RSASSA-PSS", "sun.security.rsa.RSAKeyPairGenerator$PSS", rsapssAliases, (HashMap)null);
        this.add(p, "Signature", "RSASSA-PSS", "sun.security.rsa.RSAPSSSignature", rsapssAliases, attrs);
        this.add(p, "AlgorithmParameters", "RSASSA-PSS", "sun.security.rsa.PSSParameters", rsapssAliases, (HashMap)null);
    }

    public Iterator<Service> iterator() {
        return this.services.iterator();
    }
}