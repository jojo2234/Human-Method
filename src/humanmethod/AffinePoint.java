package humanmethod;

import java.util.Objects;


public class AffinePoint {
    private final ImmutableIntegerModuloP x;
    private final ImmutableIntegerModuloP y;

    public AffinePoint(ImmutableIntegerModuloP x, ImmutableIntegerModuloP y) {
        this.x = x;
        this.y = y;
    }

    public ImmutableIntegerModuloP getX() {
        return this.x;
    }

    public ImmutableIntegerModuloP getY() {
        return this.y;
    }

    public boolean equals(Object obj) {
        if (!(obj instanceof AffinePoint)) {
            return false;
        } else {
            AffinePoint p = (AffinePoint)obj;
            boolean xEquals = this.x.asBigInteger().equals(p.x.asBigInteger());
            boolean yEquals = this.y.asBigInteger().equals(p.y.asBigInteger());
            return xEquals && yEquals;
        }
    }

    public int hashCode() {
        return Objects.hash(new Object[]{this.x, this.y});
    }

    public String toString() {
        String var10000 = this.x.asBigInteger().toString();
        return "(" + var10000 + "," + this.y.asBigInteger().toString() + ")";
    }
}
