package sha3;


import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;






public class elliptic {

	 
	private static final BigInteger p = BigInteger.valueOf(2).pow(521).subtract(BigInteger.ONE);

    private static final long d = -376014;
    private static BigInteger x;
    private static BigInteger y;
	private static byte[] theZ;
	private static byte[] theC;
    private static byte[] theT;
    private static BigInteger publicKeyV;
 
    public BigInteger getX() {
        return x;
    }

    public BigInteger getY() {
        return y;
    }
	 /*
	  * ▪ s KMACXOF256(pw, “”, 512, “K”); s <-4s
		▪ V <- s*G
	  */
	 public void generateKey(String pass) {
		 byte[] pw=pass.getBytes();
		 byte[] s1 = Shake.KMACXOF256(pw, "".getBytes(), 512, "K".getBytes());
		 BigInteger s = new BigInteger(s1).multiply(BigInteger.valueOf(4));
		 
	 }
	 
	 /*
	  * ▪ k  Random(512); k  4k
		▪ W  k*V; Z  k*G
		▪ (ke || ka)  KMACXOF256(Wx, “”, 1024, “P”)
		▪ c  KMACXOF256(ke, “”, |m|, “PKE”)  m
		▪ t  KMACXOF256(ka, m, 512, “PKA”)
		▪ cryptogram: (Z, c, t)
	  */
	 public void Encrypt(String pass ) {
		 SecureRandom random = new SecureRandom();
	     byte[] K = new byte[64];
	     random.nextBytes(K);
	     BigInteger k = new BigInteger(K).multiply(BigInteger.valueOf(4));
	     
	     CurvePoint W = CurvePoint(K,V);
	    
	     byte[] key = Shake.concat(W.getX().getBytes(), pass.getBytes());
		 byte[] keka = Shake.KMACXOF256(key, "".getBytes(), 1024, "P".getBytes());
	     byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
	     byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
		 byte[] m = Shake.addPadding(pass.getBytes(), 8);
	     byte[] c = Shake.KMACXOF256(ke, "".getBytes(), m.length, "PKE".getBytes());
	     String cHex = Symmetric.bytesToHex(c);
	     BigInteger cBigInt = new BigInteger(cHex, 16);
	     String mHex =Symmetric.bytesToHex(m);
	     BigInteger mBigInt = new BigInteger(mHex, 16);
	     cBigInt = cBigInt.xor(mBigInt);
	     theC = cBigInt.toByteArray();
	     theT = Shake.KMACXOF256(ka, pass.getBytes(), 512, "PKA".getBytes()); 
	 }
	 /*
	  * Decrypting a cryptogram (Z, c, t) under the passphrase pw:
		▪ s  KMACXOF256(pw, “”, 512, “K”); s  4s
		▪ W  s*Z
		▪ (ke || ka)  KMACXOF256(Wx, “”, 1024, “P”)
		▪ m  KMACXOF256(ke, “”, |c|, “PKE”)  c
		▪ t’  KMACXOF256(ka, m, 512, “PKA”)
		▪ accept if, and only if, t’ = t
	  */
	 public void Decrypt(String pass) {
		 byte[] key =Shake.concat(theZ, pass.getBytes()); 
	     byte[] keka = Shake.KMACXOF256(key, "".getBytes(), 1024, "P".getBytes());
	     byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
	     byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
	        
	     byte[] m = Shake.KMACXOF256(ke, "".getBytes(), theC.length, "PKE".getBytes());
	        
	    String mHex = Symmetric.bytesToHex(m);
	    BigInteger mBigInt = new BigInteger(mHex, 16);
	    String cHex = Symmetric.bytesToHex(theC);
	    BigInteger cBigInt = new BigInteger(cHex, 16);
	    mBigInt = mBigInt.xor(cBigInt);
	    m = mBigInt.toByteArray();
	    @SuppressWarnings("unused")
		byte[] Tprime = Shake.KMACXOF256(ka, m, 512, "PKA".getBytes());
	 }
	 public static BigInteger sqrt(BigInteger v, BigInteger p, boolean lsb) {
		 assert (p.testBit(0) && p.testBit(1)); // p = 3 (mod 4)
		 if (v.signum() == 0) {
		 return BigInteger.ZERO;
		 }
		 BigInteger r = v.modPow(p.shiftRight(2).add(BigInteger.ONE), p);
		 if (r.testBit(0) != lsb) {
		 r = p.subtract(r); // correct the lsb
		 }
		 return (r.multiply(r).subtract(v).mod(p).signum() == 0) ? r : null;
		}
}
