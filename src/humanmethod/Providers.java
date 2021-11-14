package humanmethod;

import java.security.Provider;

public class Providers {
    private static final ThreadLocal<ProviderList> threadLists = new InheritableThreadLocal();
    private static volatile int threadListsUsed;
    private static volatile ProviderList providerList;
    private static final String[] jarVerificationProviders;

    static void checkBouncyCastleDeprecation(String provider, String signature, String algorithm) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    static void checkBouncyCastleDeprecation(Provider provider, String signature, String algorithm) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    private Providers() {
    }

    public static Provider getSunProvider() {
        return new Sun();
    }

    public static Object startJarVerification() {
        ProviderList currentList = getProviderList();
        ProviderList jarList = currentList.getJarList(jarVerificationProviders);
        if (jarList.getProvider("SUN") == null) {
            VerificationProvider p;
            try {
                p = new VerificationProvider();
            } catch (Exception var4) {
                throw new RuntimeException("Missing provider for jar verification", var4);
            }

            ProviderList.add(jarList, p);
        }

        return beginThreadProviderList(jarList);
    }

    public static void stopJarVerification(Object obj) {
        endThreadProviderList((ProviderList)obj);
    }

    public static ProviderList getProviderList() {
        ProviderList list = getThreadProviderList();
        if (list == null) {
            list = getSystemProviderList();
        }

        return list;
    }

    public static void setProviderList(ProviderList newList) {
        if (getThreadProviderList() == null) {
            setSystemProviderList(newList);
        } else {
            changeThreadProviderList(newList);
        }

    }

    public static ProviderList getFullProviderList() {
        Class var1 = Providers.class;
        ProviderList list;
        synchronized(Providers.class) {
            list = getThreadProviderList();
            if (list != null) {
                ProviderList newList = list.removeInvalid();
                if (newList != list) {
                    changeThreadProviderList(newList);
                    list = newList;
                }

                return list;
            }
        }

        list = getSystemProviderList();
        ProviderList newList = list.removeInvalid();
        if (newList != list) {
            setSystemProviderList(newList);
            list = newList;
        }

        return list;
    }

    private static ProviderList getSystemProviderList() {
        return providerList;
    }

    private static void setSystemProviderList(ProviderList list) {
        providerList = list;
    }

    public static ProviderList getThreadProviderList() {
        return threadListsUsed == 0 ? null : (ProviderList)threadLists.get();
    }

    private static void changeThreadProviderList(ProviderList list) {
        threadLists.set(list);
    }

    public static synchronized ProviderList beginThreadProviderList(ProviderList list) {
        if (ProviderList.debug != null) {
            ProviderList.debug.println("ThreadLocal providers: " + list);
        }

        ProviderList oldList = (ProviderList)threadLists.get();
        ++threadListsUsed;
        threadLists.set(list);
        return oldList;
    }

    public static synchronized void endThreadProviderList(ProviderList list) {
        if (list == null) {
            if (ProviderList.debug != null) {
                ProviderList.debug.println("Disabling ThreadLocal providers");
            }

            threadLists.remove();
        } else {
            if (ProviderList.debug != null) {
                ProviderList.debug.println("Restoring previous ThreadLocal providers: " + list);
            }

            threadLists.set(list);
        }

        --threadListsUsed;
    }

    static {
        providerList = ProviderList.EMPTY;
        providerList = ProviderList.fromSecurityProperties();
        jarVerificationProviders = new String[]{"SUN", "SunRsaSign", "SunEC"};
    }
}