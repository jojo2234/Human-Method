package humanmethod;

public interface MutablePoint extends Point {
    MutablePoint setValue(AffinePoint var1);

    MutablePoint setValue(Point var1);

    MutablePoint conditionalSet(Point var1, int var2);
}
