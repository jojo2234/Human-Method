package humanmethod;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Properties;

public class GetPropertyAction implements PrivilegedAction<String> {
    private String theProp;
    private String defaultVal;

    public GetPropertyAction(String theProp) {
        this.theProp = theProp;
    }

    public GetPropertyAction(String theProp, String defaultVal) {
        this.theProp = theProp;
        this.defaultVal = defaultVal;
    }

    public String run() {
        String value = System.getProperty(this.theProp);
        return value == null ? this.defaultVal : value;
    }

    public static String privilegedGetProperty(String theProp) {
        return System.getSecurityManager() == null ? System.getProperty(theProp) : (String)AccessController.doPrivileged(new GetPropertyAction(theProp));
    }

    public static String privilegedGetProperty(String theProp, String defaultVal) {
        return System.getSecurityManager() == null ? System.getProperty(theProp, defaultVal) : (String)AccessController.doPrivileged(new GetPropertyAction(theProp, defaultVal));
    }

    public static Properties privilegedGetProperties() {
        return System.getSecurityManager() == null ? System.getProperties() : (Properties)AccessController.doPrivileged(new PrivilegedAction<Properties>() {
            public Properties run() {
                return System.getProperties();
            }
        });
    }
}
