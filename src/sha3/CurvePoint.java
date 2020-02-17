package sha3;

import java.math.BigInteger;

public class CurvePoint {
	private BigInteger x;

    private BigInteger y;
    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }
    private CurvePoint(BigInteger theX, BigInteger theY) {
        x = theX;
        y = theY;
    }

}
