package humanmethod;

import java.nio.ByteBuffer;

/**
 * An interface for mutable integers modulo a prime value. This interface
 * should be used to improve performance and avoid the allocation of a large
 * number of temporary objects.
 *
 * Methods in this interface that modify the value also return the modified
 * element. This structure enables fluent expressions like:
 * a.setSum(b).setProduct(c).setDifference(d).setSquare()
 *
 */

public interface MutableIntegerModuloP extends IntegerModuloP {
    void conditionalSet(IntegerModuloP var1, int var2);
    /**
     * Swap the value of this with the value of b when swap has the value 1.
     * No change is made to either element when swap has the value 0. The
     * result is undefined when swap has a value other than 0 or 1. The swap
     * parameter is an int (rather than boolean) to allow the implementation
     * to perform the swap using branch-free integer arithmetic.
     *
     * @param b the element to conditionally swap with
     * @param swap an int that determines whether to swap
     */
    void conditionalSwapWith(MutableIntegerModuloP b, int swap);

    /**
     * Set the value of this element equal to the value of the supplied
     * element. The argument is not modified.
     *
     * @param v the element whose value should be copied to this
     * @return this
     */
    MutableIntegerModuloP setValue(IntegerModuloP v);

    /**
     * Set the value equal to the little-endian unsigned integer stored at the
     * specified position in an array. The range of accepted values is
     * implementation-specific. This method also takes a byte which is
     * interpreted as an additional high-order byte of the number.
     *
     * @param v an array containing a little-endian unsigned integer
     * @param offset the starting position of the integer
     * @param length the number of bytes to read
     * @param highByte the high-order byte of the number
     * @return this
     */
    MutableIntegerModuloP setValue(byte[] v, int offset, int length,
                                   byte highByte);

    /**
     * Set the value equal to the little-endian unsigned integer stored in a
     * buffer. The range of accepted values is implementation-specific.
     * This method also takes a byte which is interpreted as an additional
     * high-order byte of the number.
     *
     * @param buf a buffer containing a little-endian unsigned integer
     * @param length the number of bytes to read
     * @param highByte the high-order byte of the number
     * @return this
     */
    MutableIntegerModuloP setValue(ByteBuffer buf, int length, byte highByte);

    /**
     * Set the value of this element equal to this * this.
     *
     * @return this
     */
    MutableIntegerModuloP setSquare();

    /**
     * Set the value of this element equal to this + b. The argument is
     * not modified.
     *
     * @param b the sumand
     * @return this
     */
    MutableIntegerModuloP setSum(IntegerModuloP b);

    /**
     * Set the value of this element equal to this - b. The argument is
     * not modified.
     *
     * @param b the subtrahend
     * @return this
     */
    MutableIntegerModuloP setDifference(IntegerModuloP b);

    /**
     * Set the value of this element equal to this * b. The argument is
     * not modified.
     *
     * @param b the multiplicand
     * @return this
     */
    MutableIntegerModuloP setProduct(IntegerModuloP b);

    /**
     * Set the value of this element equal to this * v. The argument is
     * not modified.
     *
     * @param v the small multiplicand
     * @return this
     */
    MutableIntegerModuloP setProduct(SmallValue v);
    MutableIntegerModuloP setReduced();
    MutableIntegerModuloP setAdditiveInverse();
}
