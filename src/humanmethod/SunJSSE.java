package humanmethod;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.ProviderException;
import java.security.Security;
import java.security.Provider.Service;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

public abstract class SunJSSE extends Provider {
    private static final long serialVersionUID = 3231825739635378733L;
    private static String info = "Sun JSSE provider(PKCS12, SunX509/PKIX key/trust factories, SSLv3/TLSv1/TLSv1.1/TLSv1.2/TLSv1.3/DTLSv1.0/DTLSv1.2)";
    private static String fipsInfo = "Sun JSSE provider (FIPS mode, crypto provider ";
    private static Boolean fips;
    static Provider cryptoProvider;

    protected static synchronized boolean isFIPS() {
        if (fips == null) {
            fips = false;
        }

        return fips;
    }

    private static synchronized void ensureFIPS(Provider p) {
        if (fips == null) {
            fips = true;
            cryptoProvider = p;
        } else {
            if (!fips) {
                throw new ProviderException("SunJSSE already initialized in non-FIPS mode");
            }

            if (cryptoProvider != p) {
                throw new ProviderException("SunJSSE already initialized with FIPS crypto provider " + cryptoProvider);
            }
        }

    }

    protected SunJSSE() {
        //super("SunJSSE", SecurityConstants.PROVIDER_VER, info);
        super("SunJSSE", GetPropertyAction.privilegedGetProperty("java.specification.version"), info);
        this.subclassCheck();
        if (Boolean.TRUE.equals(fips)) {
            throw new ProviderException("SunJSSE is already initialized in FIPS mode");
        } else {
            this.registerAlgorithms(false);
        }
    }

    protected SunJSSE(Provider cryptoProvider) {
        this((Provider)checkNull(cryptoProvider), cryptoProvider.getName());
    }

    protected SunJSSE(String cryptoProvider) {
        this((Provider)null, (String)checkNull(cryptoProvider));
    }

    private static <T> T checkNull(T t) {
        if (t == null) {
            throw new ProviderException("cryptoProvider must not be null");
        } else {
            return t;
        }
    }

    private SunJSSE(Provider cryptoProvider, String providerName) {
        super("SunJSSE", GetPropertyAction.privilegedGetProperty("java.specification.version"), fipsInfo + providerName + ")");
        this.subclassCheck();
        if (cryptoProvider == null) {
            cryptoProvider = Security.getProvider(providerName);
            if (cryptoProvider == null) {
                throw new ProviderException("Crypto provider not installed: " + providerName);
            }
        }

        ensureFIPS(cryptoProvider);
        this.registerAlgorithms(true);
    }

    private void registerAlgorithms(final boolean isfips) {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                SunJSSE.this.doRegister(isfips);
                return null;
            }
        });
    }

    private void ps(String type, String algo, String cn, List<String> aliases, HashMap<String, String> attrs) {
        this.putService(new Service(this, type, algo, cn, aliases, attrs));
    }

    private void doRegister(boolean isfips) {
        if (!isfips) {
            Iterator rsaIter = (new SunRsaSignEntries(this)).iterator();

            while(rsaIter.hasNext()) {
                this.putService((Service)rsaIter.next());
            }
        }

        this.ps("Signature", "MD5andSHA1withRSA", "sun.security.ssl.RSASignature", (List)null, (HashMap)null);
        this.ps("KeyManagerFactory", "SunX509", "sun.security.ssl.KeyManagerFactoryImpl$SunX509", (List)null, (HashMap)null);
        this.ps("KeyManagerFactory", "NewSunX509", "sun.security.ssl.KeyManagerFactoryImpl$X509", SunEntries.createAliases("PKIX"), (HashMap)null);
        this.ps("TrustManagerFactory", "SunX509", "sun.security.ssl.TrustManagerFactoryImpl$SimpleFactory", (List)null, (HashMap)null);
        this.ps("TrustManagerFactory", "PKIX", "sun.security.ssl.TrustManagerFactoryImpl$PKIXFactory", SunEntries.createAliases("SunPKIX", "X509", "X.509"), (HashMap)null);
        this.ps("SSLContext", "TLSv1", "sun.security.ssl.SSLContextImpl$TLS10Context", isfips ? null : SunEntries.createAliases("SSLv3"), (HashMap)null);
        this.ps("SSLContext", "TLSv1.1", "sun.security.ssl.SSLContextImpl$TLS11Context", (List)null, (HashMap)null);
        this.ps("SSLContext", "TLSv1.2", "sun.security.ssl.SSLContextImpl$TLS12Context", (List)null, (HashMap)null);
        this.ps("SSLContext", "TLSv1.3", "sun.security.ssl.SSLContextImpl$TLS13Context", (List)null, (HashMap)null);
        this.ps("SSLContext", "TLS", "sun.security.ssl.SSLContextImpl$TLSContext", isfips ? null : SunEntries.createAliases("SSL"), (HashMap)null);
        this.ps("SSLContext", "DTLSv1.0", "sun.security.ssl.SSLContextImpl$DTLS10Context", (List)null, (HashMap)null);
        this.ps("SSLContext", "DTLSv1.2", "sun.security.ssl.SSLContextImpl$DTLS12Context", (List)null, (HashMap)null);
        this.ps("SSLContext", "DTLS", "sun.security.ssl.SSLContextImpl$DTLSContext", (List)null, (HashMap)null);
        this.ps("SSLContext", "Default", "sun.security.ssl.SSLContextImpl$DefaultSSLContext", (List)null, (HashMap)null);
        this.ps("KeyStore", "PKCS12", "sun.security.pkcs12.PKCS12KeyStore", (List)null, (HashMap)null);
    }

    private void subclassCheck() {
        if(Provider.class == null){//if (this.getClass() != Provider.class) {
            throw new AssertionError("Illegal subclass: " + this.getClass());
        }
    }

    protected final void finalize() throws Throwable {
        super.finalize();
    }
}