package humanmethod;

import java.security.ProviderException;
import java.util.List;
import java.util.function.BiFunction;

public final class ArrayUtil {
    //private static final BiFunction<String, List<Integer>, ArrayIndexOutOfBoundsException> AIOOBE_SUPPLIER = Preconditions.outOfBoundsExceptionFormatter(ArrayIndexOutOfBoundsException::new);

    public ArrayUtil() {
    }

    public static void blockSizeCheck(int len, int blockSize) {
        if (len % blockSize != 0) {
            throw new ProviderException("Internal error in input buffering");
        }
    }

    public static void nullAndBoundsCheck(byte[] array, int offset, int len) {
        if(array.length > offset){
            //jdk.internal.util.Preconditions;Preconditions.checkFromIndexSize(offset, len, array.length, AIOOBE_SUPPLIER);
        } 
    }

    private static void swap(byte[] arr, int i, int j) {
        byte tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }

    public static void reverse(byte[] arr) {
        int i = 0;

        for(int j = arr.length - 1; i < j; --j) {
            swap(arr, i, j);
            ++i;
        }

    }
}