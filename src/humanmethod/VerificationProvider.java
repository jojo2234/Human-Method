package humanmethod;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Provider.Service;
import java.util.Iterator;

public final class VerificationProvider extends Provider {
    private static final long serialVersionUID = 7482667077568930381L;
    private static final boolean ACTIVE;

    public VerificationProvider() {
        super("SunJarVerification", GetPropertyAction.privilegedGetProperty("java.specification.version"), "Jar Verification Provider");
        if (ACTIVE) {
            final Iterator<Service> sunIter = (new SunEntries(this)).iterator();
            final Iterator<Service> rsaIter = (new SunRsaSignEntries(this)).iterator();
            if (System.getSecurityManager() == null) {
                this.putEntries(sunIter);
                this.putEntries(rsaIter);
            } else {
                AccessController.doPrivileged(new PrivilegedAction<Object>() {
                    public Void run() {
                        VerificationProvider.this.putEntries(sunIter);
                        VerificationProvider.this.putEntries(rsaIter);
                        return null;
                    }
                });
            }

        }
    }

    void putEntries(Iterator<Service> i) {
        while(i.hasNext()) {
            this.putService((Service)i.next());
        }

    }

    static {
        boolean b;
        try {
            Class.forName("sun.security.provider.Sun");
            Class.forName("sun.security.rsa.SunRsaSign");
            b = false;
        } catch (ClassNotFoundException var2) {
            b = true;
        }

        ACTIVE = b;
    }
}