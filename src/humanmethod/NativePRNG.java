package humanmethod;

public final class NativePRNG {
    public NativePRNG() {
    }

    static boolean isAvailable() {
        return false;
    }

    public static final class Blocking {
        public Blocking() {
        }

        static boolean isAvailable() {
            return false;
        }
    }

    public static final class NonBlocking {
        public NonBlocking() {
        }

        static boolean isAvailable() {
            return false;
        }
    }
}
