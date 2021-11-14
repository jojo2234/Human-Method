package humanmethod;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Provider.Service;
import java.util.Iterator;

public final class Sun extends Provider {
    private static final long serialVersionUID = 6440182097568097204L;
    private static final String INFO = "SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; PKCS12, JKS & DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)";

    public Sun() {
        super("SUN", GetPropertyAction.privilegedGetProperty("java.specification.version"), "SUN (DSA key/parameter generation; DSA signing; SHA-1, MD5 digests; SecureRandom; X.509 certificates; PKCS12, JKS & DKS keystores; PKIX CertPathValidator; PKIX CertPathBuilder; LDAP, Collection CertStores, JavaPolicy Policy; JavaLoginConfig Configuration)");
        final Iterator<Service> serviceIter = (new SunEntries(this)).iterator();
        if (System.getSecurityManager() == null) {
            this.putEntries(serviceIter);
        } else {
            AccessController.doPrivileged(new PrivilegedAction<Void>() {
                public Void run() {
                    Sun.this.putEntries(serviceIter);
                    return null;
                }
            });
        }

    }

    void putEntries(Iterator<Service> i) {
        while(i.hasNext()) {
            this.putService((Service)i.next());
        }

    }
}