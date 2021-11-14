package humanmethod;

import java.io.File;
import java.lang.reflect.InvocationTargetException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.InvalidParameterException;
import java.security.PrivilegedAction;
import java.security.PrivilegedExceptionAction;
import java.security.Provider;
import java.security.ProviderException;
import java.util.Iterator;
import java.util.ServiceConfigurationError;
import java.util.ServiceLoader;

final class ProviderConfig {
    private static final Debug debug = Debug.getInstance("jca", "ProviderConfig");
    private static final String P11_SOL_NAME = "SunPKCS11";
    private static final String P11_SOL_ARG = "${java.home}/conf/security/sunpkcs11-solaris.cfg";
    private static final int MAX_LOAD_TRIES = 30;
    private final String provName;
    private final String argument;
    private int tries;
    private volatile Provider provider;
    private boolean isLoading;

    ProviderConfig(String provName, String argument) {
        if (provName.endsWith("SunPKCS11") && argument.equals("${java.home}/conf/security/sunpkcs11-solaris.cfg")) {
            this.checkSunPKCS11Solaris();
        }

        this.provName = provName;
        this.argument = expand(argument);
    }

    ProviderConfig(String provName) {
        this(provName, "");
    }

    ProviderConfig(Provider provider) {
        this.provName = provider.getName();
        this.argument = "";
        this.provider = provider;
    }

    private void checkSunPKCS11Solaris() {
        Boolean o = (Boolean)AccessController.doPrivileged(new PrivilegedAction<Boolean>() {
            public Boolean run() {
                File file = new File("/usr/lib/libpkcs11.so");
                if (!file.exists()) {
                    return Boolean.FALSE;
                } else {
                    return "false".equalsIgnoreCase(System.getProperty("sun.security.pkcs11.enable-solaris")) ? Boolean.FALSE : Boolean.TRUE;
                }
            }
        });
        if (o == Boolean.FALSE) {
            this.tries = 30;
        }

    }

    private boolean hasArgument() {
        return !this.argument.isEmpty();
    }

    private boolean shouldLoad() {
        return this.tries < 30;
    }

    private void disableLoad() {
        this.tries = 30;
    }

    boolean isLoaded() {
        return this.provider != null;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (!(obj instanceof ProviderConfig)) {
            return false;
        } else {
            ProviderConfig other = (ProviderConfig)obj;
            return this.provName.equals(other.provName) && this.argument.equals(other.argument);
        }
    }

    public int hashCode() {
        return this.provName.hashCode() + this.argument.hashCode();
    }

    public String toString() {
        return this.hasArgument() ? this.provName + "('" + this.argument + "')" : this.provName;
    }

    synchronized Provider getProvider() {
        Provider p = this.provider;
        if (p != null) {
            return p;
        } else if (!this.shouldLoad()) {
            return null;
        } else {
            if (!this.provName.equals("SUN") && !this.provName.equals("sun.security.provider.Sun")) {
                if (!this.provName.equals("SunRsaSign") && !this.provName.equals("sun.security.rsa.SunRsaSign")) {
                    if (!this.provName.equals("SunJCE") && !this.provName.equals("com.sun.crypto.provider.SunJCE")) {
                        if (!this.provName.equals("SunJSSE") && !this.provName.equals("com.sun.net.ssl.internal.ssl.Provider")) {
                            if (!this.provName.equals("Apple") && !this.provName.equals("apple.security.AppleProvider")) {
                                if (this.isLoading) {
                                    if (debug != null) {
                                        debug.println("Recursion loading provider: " + this);
                                        (new Exception("Call trace")).printStackTrace();
                                    }

                                    return null;
                                }

                                try {
                                    this.isLoading = true;
                                    ++this.tries;
                                    p = this.doLoadProvider();
                                } finally {
                                    this.isLoading = false;
                                }
                            } else {
                                p = (Provider)AccessController.doPrivileged(new PrivilegedAction<Provider>() {
                                    public Provider run() {
                                        try {
                                            Class<?> c = Class.forName("apple.security.AppleProvider");
                                            if (Provider.class.isAssignableFrom(c)) {
                                                Object tmp = c.newInstance();
                                                return (Provider)tmp;
                                            } else {
                                                return null;
                                            }
                                        } catch (Exception var3) {
                                            if (ProviderConfig.debug != null) {
                                                ProviderConfig.debug.println("Error loading provider Apple");
                                                var3.printStackTrace();
                                            }

                                            return null;
                                        }
                                    }
                                });
                            }
                        } else if (this.hasArgument()) {
                            p = null;//new Provider(this.argument);
                        } else {
                            p = null;//new Provider();
                        }
                    } else {
                        p = null;//new SunJCE();
                    }
                } else {
                    p = null;//new SunRsaSign();
                }
            } else {
                p = new Sun();
            }

            this.provider = (Provider)p;
            return (Provider)p;
        }
    }

    private Provider doLoadProvider() {
        return (Provider)AccessController.doPrivileged(new PrivilegedAction<Provider>() {
            public Provider run() {
                if (ProviderConfig.debug != null) {
                    ProviderConfig.debug.println("Loading provider " + ProviderConfig.this);
                }

                try {
                    Provider p = ProviderConfig.ProviderLoader.INSTANCE.load(ProviderConfig.this.provName);
                    if (p != null) {
                        if (ProviderConfig.this.hasArgument()) {
                            p = p.configure(ProviderConfig.this.argument);
                        }

                        if (ProviderConfig.debug != null) {
                            ProviderConfig.debug.println("Loaded provider " + p.getName());
                        }
                    } else {
                        if (ProviderConfig.debug != null) {
                            ProviderConfig.debug.println("Error loading provider " + ProviderConfig.this);
                        }

                        ProviderConfig.this.disableLoad();
                    }

                    return p;
                } catch (Exception var2) {
                    if (var2 instanceof ProviderException) {
                        throw var2;
                    } else {
                        if (ProviderConfig.debug != null) {
                            ProviderConfig.debug.println("Error loading provider " + ProviderConfig.this);
                            var2.printStackTrace();
                        }

                        ProviderConfig.this.disableLoad();
                        return null;
                    }
                } catch (ExceptionInInitializerError var3) {
                    if (ProviderConfig.debug != null) {
                        ProviderConfig.debug.println("Error loading provider " + ProviderConfig.this);
                        var3.printStackTrace();
                    }

                    ProviderConfig.this.disableLoad();
                    return null;
                }
            }
        });
    }

    private static String expand(final String value) {
        return !value.contains("${") ? value : (String)AccessController.doPrivileged(new PrivilegedAction<String>() {
            public String run() {
                /*try {
                    return PropertyExpander.expand(value);
                } catch (GeneralSecurityException var2) {
                    throw new ProviderException(var2);
                }*/
                return null;
            }
        });
    }

    private static final class ProviderLoader {
        static final ProviderConfig.ProviderLoader INSTANCE = new ProviderConfig.ProviderLoader();
        private final ServiceLoader<Provider> services = ServiceLoader.load(Provider.class, ClassLoader.getSystemClassLoader());

        private ProviderLoader() {
        }

        public Provider load(String pn) {
            if (ProviderConfig.debug != null) {
                ProviderConfig.debug.println("Attempt to load " + pn + " using SL");
            }

            Iterator iter = this.services.iterator();

            while(iter.hasNext()) {
                try {
                    Provider p = (Provider)iter.next();
                    String pName = p.getName();
                    if (ProviderConfig.debug != null) {
                        ProviderConfig.debug.println("Found SL Provider named " + pName);
                    }

                    if (pName.equals(pn)) {
                        return p;
                    }
                } catch (ServiceConfigurationError | InvalidParameterException | SecurityException var7) {
                    if (ProviderConfig.debug != null) {
                        ProviderConfig.debug.println("Encountered " + var7 + " while iterating through SL, ignore and move on");
                        var7.printStackTrace();
                    }
                }
            }

            try {
                return this.legacyLoad(pn);
            } catch (ProviderException var5) {
                throw var5;
            } catch (Exception var6) {
                if (ProviderConfig.debug != null) {
                    ProviderConfig.debug.println("Encountered " + var6 + " during legacy load of " + pn);
                    var6.printStackTrace();
                }

                return null;
            }
        }

        private Provider legacyLoad(String classname) {
            if (ProviderConfig.debug != null) {
                ProviderConfig.debug.println("Loading legacy provider: " + classname);
            }

            try {
                final Class<?> provClass = ClassLoader.getSystemClassLoader().loadClass(classname);
                if (!Provider.class.isAssignableFrom(provClass)) {
                    if (ProviderConfig.debug != null) {
                        ProviderConfig.debug.println(classname + " is not a provider");
                    }

                    return null;
                } else {
                    Provider p = (Provider)AccessController.doPrivileged(new PrivilegedExceptionAction<Provider>() {
                        public Provider run() throws Exception {
                            return (Provider)provClass.newInstance();
                        }
                    });
                    return p;
                }
            } catch (Exception var4) {
                Object t;
                if (var4 instanceof InvocationTargetException) {
                    t = ((InvocationTargetException)var4).getCause();
                } else {
                    t = var4;
                }

                if (ProviderConfig.debug != null) {
                    ProviderConfig.debug.println("Error loading legacy provider " + classname);
                    ((Throwable)t).printStackTrace();
                }

                if (t instanceof ProviderException) {
                    throw (ProviderException)t;
                } else {
                    return null;
                }
            } catch (NoClassDefFoundError | ExceptionInInitializerError var5) {
                if (ProviderConfig.debug != null) {
                    ProviderConfig.debug.println("Error loading legacy provider " + classname);
                    var5.printStackTrace();
                }

                return null;
            }
        }
    }
}
