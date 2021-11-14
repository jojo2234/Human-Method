package humanmethod;

import java.security.InvalidParameterException;
import java.util.regex.PatternSyntaxException;


public final class SecurityProviderConstants {
    private static final Debug debug = Debug.getInstance("jca", "ProviderConfig");
    public static final int DEF_DSA_KEY_SIZE;
    public static final int DEF_RSA_KEY_SIZE;
    public static final int DEF_RSASSA_PSS_KEY_SIZE;
    public static final int DEF_DH_KEY_SIZE;
    public static final int DEF_EC_KEY_SIZE;
    private static final String KEY_LENGTH_PROP = "jdk.security.defaultKeySize";

    private SecurityProviderConstants() {
    }

    public static final int getDefDSASubprimeSize(int primeSize) {
        if (primeSize <= 1024) {
            return 160;
        } else if (primeSize == 2048) {
            return 224;
        } else if (primeSize == 3072) {
            return 256;
        } else {
            throw new InvalidParameterException("Invalid DSA Prime Size: " + primeSize);
        }
    }

    static {
        String keyLengthStr = GetPropertyAction.privilegedGetProperty("jdk.security.defaultKeySize");
        int dsaKeySize = 2048;
        int rsaKeySize = 2048;
        int rsaSsaPssKeySize = rsaKeySize;
        int dhKeySize = 2048;
        int ecKeySize = 256;
        if (keyLengthStr != null) {
            try {
                String[] pairs = keyLengthStr.split(",");
                String[] var7 = pairs;
                int var8 = pairs.length;

                for(int var9 = 0; var9 < var8; ++var9) {
                    String p = var7[var9];
                    String[] algoAndValue = p.split(":");
                    if (algoAndValue.length != 2) {
                        if (debug != null) {
                            debug.println("Ignoring invalid pair in jdk.security.defaultKeySize property: " + p);
                        }
                    } else {
                        String algoName = algoAndValue[0].trim().toUpperCase();
                        boolean var13 = true;

                        int value;
                        try {
                            value = Integer.parseInt(algoAndValue[1].trim());
                        } catch (NumberFormatException var15) {
                            if (debug != null) {
                                debug.println("Ignoring invalid value in jdk.security.defaultKeySize property: " + p);
                            }
                            continue;
                        }

                        if (algoName.equals("DSA")) {
                            dsaKeySize = value;
                        } else if (algoName.equals("RSA")) {
                            rsaKeySize = value;
                        } else if (algoName.equals("RSASSA-PSS")) {
                            rsaSsaPssKeySize = value;
                        } else if (algoName.equals("DH")) {
                            dhKeySize = value;
                        } else {
                            if (!algoName.equals("EC")) {
                                if (debug != null) {
                                    debug.println("Ignoring unsupported algo in jdk.security.defaultKeySize property: " + p);
                                }
                                continue;
                            }

                            ecKeySize = value;
                        }

                        if (debug != null) {
                            debug.println("Overriding default " + algoName + " keysize with value from " + "jdk.security.defaultKeySize" + " property: " + value);
                        }
                    }
                }
            } catch (PatternSyntaxException var16) {
                if (debug != null) {
                    debug.println("Unexpected exception while parsing jdk.security.defaultKeySize property: " + var16);
                }
            }
        }

        DEF_DSA_KEY_SIZE = dsaKeySize;
        DEF_RSA_KEY_SIZE = rsaKeySize;
        DEF_RSASSA_PSS_KEY_SIZE = rsaSsaPssKeySize;
        DEF_DH_KEY_SIZE = dhKeySize;
        DEF_EC_KEY_SIZE = ecKeySize;
    }
}
