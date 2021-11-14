package humanmethod;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Provider.Service;
import java.util.Iterator;
import java.util.List;

public class GetInstance {
    private GetInstance() {
    }

    public static Service getService(String type, String algorithm) throws NoSuchAlgorithmException {
        ProviderList list = Providers.getProviderList();
        Service s = list.getService(type, algorithm);
        if (s == null) {
            throw new NoSuchAlgorithmException(algorithm + " " + type + " not available");
        } else {
            return s;
        }
    }

    public static Service getService(String type, String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        if (provider != null && !provider.isEmpty()) {
            Provider p = Providers.getProviderList().getProvider(provider);
            if (p == null) {
                throw new NoSuchProviderException("no such provider: " + provider);
            } else {
                Service s = p.getService(type, algorithm);
                if (s == null) {
                    throw new NoSuchAlgorithmException("no such algorithm: " + algorithm + " for provider " + provider);
                } else {
                    return s;
                }
            }
        } else {
            throw new IllegalArgumentException("missing provider");
        }
    }

    public static Service getService(String type, String algorithm, Provider provider) throws NoSuchAlgorithmException {
        if (provider == null) {
            throw new IllegalArgumentException("missing provider");
        } else {
            Service s = provider.getService(type, algorithm);
            if (s == null) {
                throw new NoSuchAlgorithmException("no such algorithm: " + algorithm + " for provider " + provider.getName());
            } else {
                return s;
            }
        }
    }

    public static List<Service> getServices(String type, String algorithm) {
        ProviderList list = Providers.getProviderList();
        return list.getServices(type, algorithm);
    }

    /** @deprecated */
    @Deprecated
    public static List<Service> getServices(String type, List<String> algorithms) {
        ProviderList list = Providers.getProviderList();
        return list.getServices(type, algorithms);
    }

    public static List<Service> getServices(List<ServiceId> ids) {
        ProviderList list = Providers.getProviderList();
        return list.getServices(ids);
    }

    public static GetInstance.Instance getInstance(String type, Class<?> clazz, String algorithm) throws NoSuchAlgorithmException {
        ProviderList list = Providers.getProviderList();
        Service firstService = list.getService(type, algorithm);
        if (firstService == null) {
            throw new NoSuchAlgorithmException(algorithm + " " + type + " not available");
        } else {
            try {
                return getInstance(firstService, clazz);
            } catch (NoSuchAlgorithmException var10) {
                NoSuchAlgorithmException failure = var10;
                Iterator var6 = list.getServices(type, algorithm).iterator();

                while(true) {
                    Service s;
                    do {
                        if (!var6.hasNext()) {
                            throw failure;
                        }

                        s = (Service)var6.next();
                    } while(s == firstService);

                    try {
                        return getInstance(s, clazz);
                    } catch (NoSuchAlgorithmException var9) {
                        failure = var9;
                    }
                }
            }
        }
    }

    public static GetInstance.Instance getInstance(String type, Class<?> clazz, String algorithm, Object param) throws NoSuchAlgorithmException {
        List<Service> services = getServices(type, algorithm);
        NoSuchAlgorithmException failure = null;
        Iterator var6 = services.iterator();

        while(var6.hasNext()) {
            Service s = (Service)var6.next();

            try {
                return getInstance(s, clazz, param);
            } catch (NoSuchAlgorithmException var9) {
                failure = var9;
            }
        }

        if (failure != null) {
            throw failure;
        } else {
            throw new NoSuchAlgorithmException(algorithm + " " + type + " not available");
        }
    }

    public static GetInstance.Instance getInstance(String type, Class<?> clazz, String algorithm, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        return getInstance(getService(type, algorithm, provider), clazz);
    }

    public static GetInstance.Instance getInstance(String type, Class<?> clazz, String algorithm, Object param, String provider) throws NoSuchAlgorithmException, NoSuchProviderException {
        return getInstance(getService(type, algorithm, provider), clazz, param);
    }

    public static GetInstance.Instance getInstance(String type, Class<?> clazz, String algorithm, Provider provider) throws NoSuchAlgorithmException {
        return getInstance(getService(type, algorithm, provider), clazz);
    }

    public static GetInstance.Instance getInstance(String type, Class<?> clazz, String algorithm, Object param, Provider provider) throws NoSuchAlgorithmException {
        return getInstance(getService(type, algorithm, provider), clazz, param);
    }

    public static GetInstance.Instance getInstance(Service s, Class<?> clazz) throws NoSuchAlgorithmException {
        Object instance = s.newInstance((Object)null);
        checkSuperClass(s, instance.getClass(), clazz);
        return new GetInstance.Instance(s.getProvider(), instance);
    }

    public static GetInstance.Instance getInstance(Service s, Class<?> clazz, Object param) throws NoSuchAlgorithmException {
        Object instance = s.newInstance(param);
        checkSuperClass(s, instance.getClass(), clazz);
        return new GetInstance.Instance(s.getProvider(), instance);
    }

    public static void checkSuperClass(Service s, Class<?> subClass, Class<?> superClass) throws NoSuchAlgorithmException {
        if (superClass != null) {
            if (!superClass.isAssignableFrom(subClass)) {
                throw new NoSuchAlgorithmException("class configured for " + s.getType() + ": " + s.getClassName() + " not a " + s.getType());
            }
        }
    }

    public static final class Instance {
        public final Provider provider;
        public final Object impl;

        private Instance(Provider provider, Object impl) {
            this.provider = provider;
            this.impl = impl;
        }

        public Object[] toArray() {
            return new Object[]{this.impl, this.provider};
        }
    }
}