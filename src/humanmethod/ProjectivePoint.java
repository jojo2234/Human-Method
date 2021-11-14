package humanmethod;

public abstract class ProjectivePoint<T extends IntegerModuloP> implements Point {
    protected final T x;
    protected final T y;
    protected final T z;

    protected ProjectivePoint(T x, T y, T z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }

    public IntegerFieldModuloP getField() {
        return this.x.getField();
    }

    public ProjectivePoint.Immutable fixed() {
        return new ProjectivePoint.Immutable(this.x.fixed(), this.y.fixed(), this.z.fixed());
    }

    public ProjectivePoint.Mutable mutable() {
        return new ProjectivePoint.Mutable(this.x.mutable(), this.y.mutable(), this.z.mutable());
    }

    public T getX() {
        return this.x;
    }

    public T getY() {
        return this.y;
    }

    public T getZ() {
        return this.z;
    }

    public AffinePoint asAffine() {
        IntegerModuloP zInv = this.z.multiplicativeInverse();
        return new AffinePoint(this.x.multiply(zInv), this.y.multiply(zInv));
    }

    public static class Mutable extends ProjectivePoint<MutableIntegerModuloP> implements MutablePoint {
        public Mutable(MutableIntegerModuloP x, MutableIntegerModuloP y, MutableIntegerModuloP z) {
            super(x, y, z);
        }

        public Mutable(IntegerFieldModuloP field) {
            super(field.get0().mutable(), field.get0().mutable(), field.get0().mutable());
        }

        public ProjectivePoint.Mutable conditionalSet(Point p, int set) {
            if (!(p instanceof ProjectivePoint)) {
                throw new RuntimeException("Incompatible point");
            } else {
                ProjectivePoint<IntegerModuloP> pp = (ProjectivePoint)p;
                return this.conditionalSet(pp, set);
            }
        }

        private <T extends IntegerModuloP> ProjectivePoint.Mutable conditionalSet(ProjectivePoint<T> pp, int set) {
            ((MutableIntegerModuloP)this.x).conditionalSet(pp.x, set);
            ((MutableIntegerModuloP)this.y).conditionalSet(pp.y, set);
            ((MutableIntegerModuloP)this.z).conditionalSet(pp.z, set);
            return this;
        }

        public ProjectivePoint.Mutable setValue(AffinePoint p) {
            ((MutableIntegerModuloP)this.x).setValue(p.getX());
            ((MutableIntegerModuloP)this.y).setValue(p.getY());
            ((MutableIntegerModuloP)this.z).setValue(p.getX().getField().get1());
            return this;
        }

        public ProjectivePoint.Mutable setValue(Point p) {
            if (!(p instanceof ProjectivePoint)) {
                throw new RuntimeException("Incompatible point");
            } else {
                ProjectivePoint<IntegerModuloP> pp = (ProjectivePoint)p;
                return this.setValue(pp);
            }
        }

        private <T extends IntegerModuloP> ProjectivePoint.Mutable setValue(ProjectivePoint<T> pp) {
            ((MutableIntegerModuloP)this.x).setValue(pp.x);
            ((MutableIntegerModuloP)this.y).setValue(pp.y);
            ((MutableIntegerModuloP)this.z).setValue(pp.z);
            return this;
        }
    }

    public static class Immutable extends ProjectivePoint<ImmutableIntegerModuloP> implements ImmutablePoint {
        public Immutable(ImmutableIntegerModuloP x, ImmutableIntegerModuloP y, ImmutableIntegerModuloP z) {
            super(x, y, z);
        }
    }
}
