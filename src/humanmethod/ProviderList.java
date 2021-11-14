package humanmethod;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;
import java.security.Security;
import java.security.Provider.Service;
import java.util.AbstractList;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;
import java.util.NoSuchElementException;

public final class ProviderList {
    static final Debug debug = Debug.getInstance("jca", "ProviderList");
    private static final ProviderConfig[] PC0 = new ProviderConfig[0];
    private static final Provider[] P0 = new Provider[0];
    static final ProviderList EMPTY;
    private static ProviderList.PreferredList preferredPropList;
    private static final Provider EMPTY_PROVIDER;
    private final ProviderConfig[] configs;
    private volatile boolean allLoaded;
    private final List<Provider> userList;
    private static final String[] SHA2Group;
    private static final String[] HmacSHA2Group;
    private static final String[] SHA2RSAGroup;
    private static final String[] SHA2DSAGroup;
    private static final String[] SHA2ECDSAGroup;
    private static final String[] SHA3Group;
    private static final String[] HmacSHA3Group;

    static ProviderList fromSecurityProperties() {
        return (ProviderList)AccessController.doPrivileged(new PrivilegedAction<ProviderList>() {
            public ProviderList run() {
                return new ProviderList();
            }
        });
    }

    public static ProviderList add(ProviderList providerList, Provider p) {
        return insertAt(providerList, p, -1);
    }

    public static ProviderList insertAt(ProviderList providerList, Provider p, int position) {
        if (providerList.getProvider(p.getName()) != null) {
            return providerList;
        } else {
            List<ProviderConfig> list = new ArrayList(Arrays.asList(providerList.configs));
            int n = list.size();
            if (position < 0 || position > n) {
                position = n;
            }

            list.add(position, new ProviderConfig(p));
            return new ProviderList((ProviderConfig[])list.toArray(PC0), true);
        }
    }

    public static ProviderList remove(ProviderList providerList, String name) {
        if (providerList.getProvider(name) == null) {
            return providerList;
        } else {
            ProviderConfig[] configs = new ProviderConfig[providerList.size() - 1];
            int j = 0;
            ProviderConfig[] var4 = providerList.configs;
            int var5 = var4.length;

            for(int var6 = 0; var6 < var5; ++var6) {
                ProviderConfig config = var4[var6];
                if (!config.getProvider().getName().equals(name)) {
                    configs[j++] = config;
                }
            }

            return new ProviderList(configs, true);
        }
    }

    public static ProviderList newList(Provider... providers) {
        ProviderConfig[] configs = new ProviderConfig[providers.length];

        for(int i = 0; i < providers.length; ++i) {
            configs[i] = new ProviderConfig(providers[i]);
        }

        return new ProviderList(configs, true);
    }

    private ProviderList(ProviderConfig[] configs, boolean allLoaded) {
        this.userList = new ArrayList();
        this.configs = configs;
        this.allLoaded = allLoaded;
    }

    private ProviderList() {
        class NamelessClass_1 extends AbstractList<Provider> {
            NamelessClass_1() {
            }

            public int size() {
                return ProviderList.this.configs.length;
            }

            public Provider get(int index) {
                return ProviderList.this.getProvider(index);
            }
        }

        this.userList = new NamelessClass_1();
        List<ProviderConfig> configList = new ArrayList();

        String entry;
        int i;
        for(i = 1; (entry = Security.getProperty("security.provider." + i)) != null; ++i) {
            entry = entry.trim();
            if (entry.isEmpty()) {
                System.err.println("invalid entry for security.provider." + i);
                break;
            }

            int k = entry.indexOf(32);
            ProviderConfig config;
            if (k == -1) {
                config = new ProviderConfig(entry);
            } else {
                String provName = entry.substring(0, k);
                String argument = entry.substring(k + 1).trim();
                config = new ProviderConfig(provName, argument);
            }

            if (!configList.contains(config)) {
                configList.add(config);
            }
        }

        this.configs = (ProviderConfig[])configList.toArray(PC0);
        entry = Security.getProperty("jdk.security.provider.preferred");
        if (entry != null && !(entry = entry.trim()).isEmpty()) {
            String[] entries = entry.split(",");
            if (preferredPropList == null) {
                preferredPropList = new ProviderList.PreferredList();
            }

            String[] var10 = entries;
            int var11 = entries.length;

            for(int var12 = 0; var12 < var11; ++var12) {
                String e = var10[var12];
                i = e.indexOf(58);
                if (i < 0) {
                    if (debug != null) {
                        debug.println("invalid preferred entry skipped.  Missing colon delimiter \"" + e + "\"");
                    }
                } else {
                    preferredPropList.add(new ProviderList.PreferredEntry(e.substring(0, i).trim(), e.substring(i + 1).trim()));
                }
            }
        }

        if (debug != null) {
            debug.println("provider configuration: " + configList);
            debug.println("config configuration: " + preferredPropList);
        }

    }

    ProviderList getJarList(String[] jarProvNames) {
        List<ProviderConfig> newConfigs = new ArrayList();
        String[] var3 = jarProvNames;
        int var4 = jarProvNames.length;

        for(int var5 = 0; var5 < var4; ++var5) {
            String provName = var3[var5];
            ProviderConfig newConfig = new ProviderConfig(provName);
            ProviderConfig[] var8 = this.configs;
            int var9 = var8.length;

            for(int var10 = 0; var10 < var9; ++var10) {
                ProviderConfig config = var8[var10];
                if (config.equals(newConfig)) {
                    newConfig = config;
                    break;
                }
            }

            newConfigs.add(newConfig);
        }

        ProviderConfig[] configArray = (ProviderConfig[])newConfigs.toArray(PC0);
        return new ProviderList(configArray, false);
    }

    public int size() {
        return this.configs.length;
    }

    Provider getProvider(int index) {
        Provider p = this.configs[index].getProvider();
        return p != null ? p : EMPTY_PROVIDER;
    }

    public List<Provider> providers() {
        return this.userList;
    }

    private ProviderConfig getProviderConfig(String name) {
        int index = this.getIndex(name);
        return index != -1 ? this.configs[index] : null;
    }

    public Provider getProvider(String name) {
        ProviderConfig config = this.getProviderConfig(name);
        return config == null ? null : config.getProvider();
    }

    public int getIndex(String name) {
        for(int i = 0; i < this.configs.length; ++i) {
            Provider p = this.getProvider(i);
            if (p.getName().equals(name)) {
                return i;
            }
        }

        return -1;
    }

    private int loadAll() {
        if (this.allLoaded) {
            return this.configs.length;
        } else {
            if (debug != null) {
                debug.println("Loading all providers");
                (new Exception("Debug Info. Call trace:")).printStackTrace();
            }

            int n = 0;

            for(int i = 0; i < this.configs.length; ++i) {
                Provider p = this.configs[i].getProvider();
                if (p != null) {
                    ++n;
                }
            }

            if (n == this.configs.length) {
                this.allLoaded = true;
            }

            return n;
        }
    }

    ProviderList removeInvalid() {
        int n = this.loadAll();
        if (n == this.configs.length) {
            return this;
        } else {
            ProviderConfig[] newConfigs = new ProviderConfig[n];
            int i = 0;

            for(int var4 = 0; i < this.configs.length; ++i) {
                ProviderConfig config = this.configs[i];
                if (config.isLoaded()) {
                    newConfigs[var4++] = config;
                }
            }

            return new ProviderList(newConfigs, true);
        }
    }

    public Provider[] toArray() {
        return (Provider[])this.providers().toArray(P0);
    }

    public String toString() {
        return Arrays.asList(this.configs).toString();
    }

    public Service getService(String type, String name) {
        ArrayList<ProviderList.PreferredEntry> pList = null;
        int i;
        Provider p;
        Service s;
        if (preferredPropList != null && (pList = preferredPropList.getAll(type, name)) != null) {
            for(i = 0; i < pList.size(); ++i) {
                p = this.getProvider(((ProviderList.PreferredEntry)pList.get(i)).provider);
                s = p.getService(type, name);
                if (s != null) {
                    return s;
                }
            }
        }

        for(i = 0; i < this.configs.length; ++i) {
            p = this.getProvider(i);
            s = p.getService(type, name);
            if (s != null) {
                return s;
            }
        }

        return null;
    }

    public List<Service> getServices(String type, String algorithm) {
        return new ProviderList.ServiceList(type, algorithm);
    }

    /** @deprecated */
    @Deprecated
    public List<Service> getServices(String type, List<String> algorithms) {
        List<ServiceId> ids = new ArrayList();
        Iterator var4 = algorithms.iterator();

        while(var4.hasNext()) {
            String alg = (String)var4.next();
            ids.add(new ServiceId(type, alg));
        }

        return this.getServices(ids);
    }

    public List<Service> getServices(List<ServiceId> ids) {
        return new ProviderList.ServiceList(ids);
    }

    static {
        EMPTY = new ProviderList(PC0, true);
        preferredPropList = null;
        EMPTY_PROVIDER = new Provider("##Empty##", "1.0", "initialization in progress") {
            private static final long serialVersionUID = 1151354171352296389L;

            public Service getService(String type, String algorithm) {
                return null;
            }
        };
        SHA2Group = new String[]{"SHA-224", "SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"};
        HmacSHA2Group = new String[]{"HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512"};
        SHA2RSAGroup = new String[]{"SHA224withRSA", "SHA256withRSA", "SHA384withRSA", "SHA512withRSA"};
        SHA2DSAGroup = new String[]{"SHA224withDSA", "SHA256withDSA", "SHA384withDSA", "SHA512withDSA"};
        SHA2ECDSAGroup = new String[]{"SHA224withECDSA", "SHA256withECDSA", "SHA384withECDSA", "SHA512withECDSA"};
        SHA3Group = new String[]{"SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512"};
        HmacSHA3Group = new String[]{"HmacSHA3-224", "HmacSHA3-256", "HmacSHA3-384", "HmacSHA3-512"};
    }

    private static class PreferredEntry {
        private String type = null;
        private String algorithm;
        private String provider;
        private String[] alternateNames = null;
        private boolean group = false;

        PreferredEntry(String t, String p) {
            int i = t.indexOf(46);
            if (i > 0) {
                this.type = t.substring(0, i);
                this.algorithm = t.substring(i + 1);
            } else {
                this.algorithm = t;
            }

            this.provider = p;
            if (this.type != null && this.type.compareToIgnoreCase("Group") == 0) {
                if (this.algorithm.compareToIgnoreCase("SHA2") == 0) {
                    this.alternateNames = ProviderList.SHA2Group;
                } else if (this.algorithm.compareToIgnoreCase("HmacSHA2") == 0) {
                    this.alternateNames = ProviderList.HmacSHA2Group;
                } else if (this.algorithm.compareToIgnoreCase("SHA2RSA") == 0) {
                    this.alternateNames = ProviderList.SHA2RSAGroup;
                } else if (this.algorithm.compareToIgnoreCase("SHA2DSA") == 0) {
                    this.alternateNames = ProviderList.SHA2DSAGroup;
                } else if (this.algorithm.compareToIgnoreCase("SHA2ECDSA") == 0) {
                    this.alternateNames = ProviderList.SHA2ECDSAGroup;
                } else if (this.algorithm.compareToIgnoreCase("SHA3") == 0) {
                    this.alternateNames = ProviderList.SHA3Group;
                } else if (this.algorithm.compareToIgnoreCase("HmacSHA3") == 0) {
                    this.alternateNames = ProviderList.HmacSHA3Group;
                }

                if (this.alternateNames != null) {
                    this.group = true;
                }
            } else if (this.algorithm.compareToIgnoreCase("SHA1") == 0) {
                this.alternateNames = new String[]{"SHA-1"};
            } else if (this.algorithm.compareToIgnoreCase("SHA-1") == 0) {
                this.alternateNames = new String[]{"SHA1"};
            }

        }

        boolean match(String t, String a) {
            if (ProviderList.debug != null) {
                ProviderList.debug.println("Config check:  " + this.toString() + " == " + this.print(t, a, (String)null));
            }

            if (this.type != null && !this.group && this.type.compareToIgnoreCase(t) != 0) {
                return false;
            } else if (!this.group && a.compareToIgnoreCase(this.algorithm) == 0) {
                if (ProviderList.debug != null) {
                    ProviderList.debug.println("Config entry matched:  " + this.toString());
                }

                return true;
            } else {
                if (this.alternateNames != null) {
                    String[] var3 = this.alternateNames;
                    int var4 = var3.length;

                    for(int var5 = 0; var5 < var4; ++var5) {
                        String alt = var3[var5];
                        if (ProviderList.debug != null) {
                            ProviderList.debug.println("AltName check:  " + this.print(this.type, alt, this.provider));
                        }

                        if (a.compareToIgnoreCase(alt) == 0) {
                            if (ProviderList.debug != null) {
                                ProviderList.debug.println("AltName entry matched:  " + this.provider);
                            }

                            return true;
                        }
                    }
                }

                return false;
            }
        }

        private String print(String t, String a, String p) {
            return "[" + (t != null ? t : "") + ", " + a + (p != null ? " : " + p : "") + "] ";
        }

        public String toString() {
            return this.print(this.type, this.algorithm, this.provider);
        }
    }

    static final class PreferredList {
        ArrayList<ProviderList.PreferredEntry> list = new ArrayList();

        PreferredList() {
        }

        ArrayList<ProviderList.PreferredEntry> getAll(ProviderList.ServiceList s) {
            if (s.ids == null) {
                return this.getAll(s.type, s.algorithm);
            } else {
                ArrayList<ProviderList.PreferredEntry> l = new ArrayList();
                Iterator var3 = s.ids.iterator();

                while(var3.hasNext()) {
                    ServiceId id = (ServiceId)var3.next();
                    this.implGetAll(l, id.type, id.algorithm);
                }

                return l;
            }
        }

        ArrayList<ProviderList.PreferredEntry> getAll(String type, String algorithm) {
            ArrayList<ProviderList.PreferredEntry> l = new ArrayList();
            this.implGetAll(l, type, algorithm);
            return l;
        }

        private void implGetAll(ArrayList<ProviderList.PreferredEntry> l, String type, String algorithm) {
            for(int i = 0; i < this.size(); ++i) {
                ProviderList.PreferredEntry e = (ProviderList.PreferredEntry)this.list.get(i);
                if (e.match(type, algorithm)) {
                    l.add(e);
                }
            }

        }

        public ProviderList.PreferredEntry get(int i) {
            return (ProviderList.PreferredEntry)this.list.get(i);
        }

        public int size() {
            return this.list.size();
        }

        public boolean add(ProviderList.PreferredEntry e) {
            return this.list.add(e);
        }

        public String toString() {
            String s = "";

            ProviderList.PreferredEntry e;
            for(Iterator var2 = this.list.iterator(); var2.hasNext(); s = s + e.toString()) {
                e = (ProviderList.PreferredEntry)var2.next();
            }

            return s;
        }
    }

    private final class ServiceList extends AbstractList<Service> {
        private final String type;
        private final String algorithm;
        private final List<ServiceId> ids;
        private Service firstService;
        private List<Service> services;
        private int providerIndex = 0;
        ArrayList<ProviderList.PreferredEntry> preferredList = null;
        private int preferredIndex = 0;

        ServiceList(String type, String algorithm) {
            this.type = type;
            this.algorithm = algorithm;
            this.ids = null;
        }

        ServiceList(List<ServiceId> ids) {
            this.type = null;
            this.algorithm = null;
            this.ids = ids;
        }

        private void addService(Service s) {
            if (this.firstService == null) {
                this.firstService = s;
            } else {
                if (this.services == null) {
                    this.services = new ArrayList(4);
                    this.services.add(this.firstService);
                }

                this.services.add(s);
            }

        }

        private Service tryGet(int index) {
            if (ProviderList.preferredPropList != null && this.preferredList == null) {
                this.preferredList = ProviderList.preferredPropList.getAll(this);
            }

            while(true) {
                while(index != 0 || this.firstService == null) {
                    if (this.services != null && this.services.size() > index) {
                        return (Service)this.services.get(index);
                    }

                    if (this.providerIndex >= ProviderList.this.configs.length) {
                        return null;
                    }

                    Provider p;
                    if (this.preferredList != null && this.preferredIndex < this.preferredList.size()) {
                        ProviderList.PreferredEntry entry = (ProviderList.PreferredEntry)this.preferredList.get(this.preferredIndex++);
                        p = ProviderList.this.getProvider(entry.provider);
                        if (p == null) {
                            if (ProviderList.debug != null) {
                                ProviderList.debug.println("No provider found with name: " + entry.provider);
                            }
                            continue;
                        }
                    } else {
                        p = ProviderList.this.getProvider(this.providerIndex++);
                    }

                    if (this.type != null) {
                        Service s = p.getService(this.type, this.algorithm);
                        if (s != null) {
                            this.addService(s);
                        }
                    } else {
                        Iterator var6 = this.ids.iterator();

                        while(var6.hasNext()) {
                            ServiceId id = (ServiceId)var6.next();
                            Service sx = p.getService(id.type, id.algorithm);
                            if (sx != null) {
                                this.addService(sx);
                            }
                        }
                    }
                }

                return this.firstService;
            }
        }

        public Service get(int index) {
            Service s = this.tryGet(index);
            if (s == null) {
                throw new IndexOutOfBoundsException();
            } else {
                return s;
            }
        }

        public int size() {
            int n;
            if (this.services != null) {
                n = this.services.size();
            } else {
                n = this.firstService != null ? 1 : 0;
            }

            while(this.tryGet(n) != null) {
                ++n;
            }

            return n;
        }

        public boolean isEmpty() {
            return this.tryGet(0) == null;
        }

        public Iterator<Service> iterator() {
            return new Iterator<Service>() {
                int index;

                public boolean hasNext() {
                    return ServiceList.this.tryGet(this.index) != null;
                }

                public Service next() {
                    Service s = ServiceList.this.tryGet(this.index);
                    if (s == null) {
                        throw new NoSuchElementException();
                    } else {
                        ++this.index;
                        return s;
                    }
                }

                public void remove() {
                    throw new UnsupportedOperationException();
                }
            };
        }
    }
}
