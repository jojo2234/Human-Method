package humanmethod;

public final class Provider extends SunJSSE {
    private static final long serialVersionUID = 3231825739635378733L;

    public Provider() {
    }

    public Provider(java.security.Provider cryptoProvider) {
        super(cryptoProvider);
    }

    public Provider(String cryptoProvider) {
        super(cryptoProvider);
    }

    public static synchronized boolean isFIPS() {
        return SunJSSE.isFIPS();
    }

    public static synchronized void install() {
    }
}
