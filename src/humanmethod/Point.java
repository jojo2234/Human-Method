package humanmethod;


public interface Point {
    IntegerFieldModuloP getField();

    AffinePoint asAffine();

    ImmutablePoint fixed();

    MutablePoint mutable();
}
