package sha3;

import java.util.Arrays;
/**
 * 
 * @author Yunhan Tu
 * @author Markku-Juhani Saarinen,  Paulo S. L. M. Barreto
 */
public class Shake {

	private byte[] b = new byte[200];	
    private int pt, rsiz, mdlen;	
	private static final int KECCAKF_ROUNDS = 24;

	private boolean ext = false, kmac = false;
    private static final byte[] KMAC_N = {(byte)0x4B, (byte)0x4D, (byte)0x41, (byte)0x43}; 
    
    
    
    private static final byte[] theRightEncode = {(byte)0x00, (byte)0x01}; 
    private static final byte[] theLeftEncode = {(byte)0x01, (byte)0x00};
    
    
    private static final long[] keccakf_rndc = {
		0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
		0x8000000080008000L, 0x000000000000808bL, 0x0000000080000001L,
		0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
		0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
		0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
		0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
		0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
		0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
	};
    
    private static final int[] keccakf_rotc = {
    		1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
    		27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    	};

   
    private static final int[] keccakf_piln = {
    		10, 7,  11, 17, 18, 3, 5,  16, 8,  21, 24, 4,
    		15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    	};
    public Shake() {}

    private static void sha3_keccakf(byte[] v) {
		long[] q = new long[25]; // 64-bit words
		long[] bc = new long[5];

		// map from bytes (in v[]) to longs (in q[]).
		for (int i = 0, j = 0; i < 25; i++, j += 8) {
			q[i] =  (((long)v[j + 0] & 0xFFL)      ) | (((long)v[j + 1] & 0xFFL) <<  8) |
					(((long)v[j + 2] & 0xFFL) << 16) | (((long)v[j + 3] & 0xFFL) << 24) |
					(((long)v[j + 4] & 0xFFL) << 32) | (((long)v[j + 5] & 0xFFL) << 40) |
					(((long)v[j + 6] & 0xFFL) << 48) | (((long)v[j + 7] & 0xFFL) << 56);
		}

		// actual iteration
		for (int r = 0; r < KECCAKF_ROUNDS; r++) {

			// Theta
			for (int i = 0; i < 5; i++) {
                bc[i] = q[i] ^ q[i + 5] ^ q[i + 10] ^ q[i + 15] ^ q[i + 20];
            }
			for (int i = 0; i < 5; i++) {
				long t = bc[(i + 4) % 5] ^ ROTL64(bc[(i + 1) % 5], 1);
				for (int j = 0; j < 25; j += 5) {
					q[j + i] ^= t;
				}
			}

			// Rho Pi
			long t = q[1];
			for (int i = 0; i < 24; i++) {
				int j = keccakf_piln[i];
				bc[0] = q[j];
				q[j] = ROTL64(t, keccakf_rotc[i]);
				t = bc[0];
			}

			//  Chi
			for (int j = 0; j < 25; j += 5) {
				for (int i = 0; i < 5; i++) {
                    bc[i] = q[j + i];
                }
				for (int i = 0; i < 5; i++) {
                    q[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
                }
			}

			//  Iota
			q[0] ^= keccakf_rndc[r];
		}

		// map from longs (in q[]) to bytes (in v[]).
		for (int i = 0, j = 0; i < 25; i++, j += 8) {
			long t = q[i];
			v[j + 0] = (byte)((t      ) & 0xFF);
			v[j + 1] = (byte)((t >>  8) & 0xFF);
			v[j + 2] = (byte)((t >> 16) & 0xFF);
			v[j + 3] = (byte)((t >> 24) & 0xFF);
			v[j + 4] = (byte)((t >> 32) & 0xFF);
			v[j + 5] = (byte)((t >> 40) & 0xFF);
			v[j + 6] = (byte)((t >> 48) & 0xFF);
			v[j + 7] = (byte)((t >> 56) & 0xFF);
		}
	}
    
    private static long ROTL64(long x, int y) {
		return (x << y) | (x >>> (64 - y));
	}



    public void init256() {
        Arrays.fill(this.b, (byte)0);
        this.mdlen = 32; // fixed for SHAKE256 (for SHA128 it would be 16)
        this.rsiz = 200 - 2*mdlen;
        this.pt = 0;

        this.ext = false;
        this.kmac = false;
    }

    public void update(byte[] data, int len) {
		int j = this.pt;
		for (int i = 0; i < len; i++) {
			this.b[j++] ^= data[i];
			if (j >= this.rsiz) {
				sha3_keccakf(b);
				j = 0;
			}
		}
		this.pt = j;
	}

    public void xof() {
        if (kmac) {
            update(theRightEncode, theRightEncode.length); 
        }
    	
    	this.b[this.pt] ^= (byte)(this.ext ? 0x04 : 0x1F);
		this.b[this.rsiz - 1] ^= (byte)0x80;
		sha3_keccakf(b);
		this.pt = 0;
	}


    public void out(byte[] out, int len) {
		int j = pt;
		for (int i = 0; i < len; i++) {
			if (j >= rsiz) {
				sha3_keccakf(b);
				j = 0;
			}
			out[i] = b[j++];
		}
		pt = j;
	}
    
   
  
//    private static byte[] left_encode(int x) {
//    	 /*
//         * Validity Conditions: 0 ≤ x < 22040
//    		1. Let n be the smallest positive integer for which 28n > x.
//    		2. Let x1, x2, …, xn be the base-256 encoding of x satisfying:
//    		x = ∑ 28(n-i)
//    		xi, for i = 1 to n.
//    		3. Let Oi = enc8(xi), for i = 1 to n.
//    		4. Let O0 = enc8(n).
//    		5. Return O = O0 || O1 || … || On−1 || On.
//         */
//        
//        int n = 1;
//        while ((1 << (8*n)) <= x) n++;
//        byte[] myO = new byte[n + 1];
//        for (int i = n; i > 0; i--) {
//            myO[i] = (byte)(x & 0xFF);
//            x >>>= 8;
//        }
//        myO[0] = (byte)n;
//        
//        return myO;
//    }

    
    private static byte[] left_encode(int x) {
        // Validity Conditions: 0 鈮� x < 2^2040
        // 1. Let n be the smallest positive integer for which 2^(8*n) > x.
        int n = 1;
        while ((1 << (8*n)) <= x) {
            n++;
        }
        if (n >= 256) {
            throw new RuntimeException("Left encoding overflow for length " + n);
        }
        // 2. Let x1, x2, ..., xn be the base-256 encoding of x satisfying:
        //    x = 危 2^(8*(n-i))*x_i, for i = 1 to n.
        // 3. Let Oi = enc8(xi), for i = 1 to n.
        byte[] val = new byte[n + 1];
        for (int i = n; i > 0; i--) {
            val[i] = (byte)(x & 0xFF);
            x >>>= 8;
        }
        // 4. Let O0 = enc8(n).
        val[0] = (byte)n;
        // 5. Return O = O0 || O1 || 鈥| On鈭�1 || On.
        return val;
    }
   
    private static byte[] right_encode(int x) {
	 /*right_encode(x):
		Validity Conditions: 0 ≤ x < 2 2040
		1. Let n be the smallest positive integer for which 2^8n > x.
		2. Let x 1 , x 2 ,..., x n be the base-256 encoding of x satisfying:
		x = ∑ 2 8(n-i) x i , for i = 1 to n.
		3. Let O i = enc 8 (x i ), for i = 1 to n.
		4. Let O n+1 = enc 8 (n).
		5. Return O = O 1 || O 2 || ... || O n || O n+1 .
	*/
		int n =1, i;
		int temp = x;
		while (1 << 8*n < x)n++;
		byte[] myO = new byte[n+1];
		for (i=1; i < n; i++) {
			myO[n - 1 - i] = (byte) (temp & 0xFF);
			temp >>>= 8;
		}
		myO[myO.length-1] = (byte) n;
		
		return myO;
    }
    
   
    static byte[] concat(byte[] a, byte[] b) {
    	int i = 0, j= 0;
    	if(a != null ) {
    		i = a.length;
    	}
    	if(b != null ) {
    		j = b.length;
    	}
        
        byte[] c = new byte[i + j];
        System.arraycopy(a, 0, c, 0, i);
        System.arraycopy(b, 0, c, i, j);
        return c;
    }
    
    public void cinit256(byte[] N, byte[] S) {
        // Validity Conditions: len(N) < 2^2040 and len(S) < 2^2040
        init256();
        if ((N != null && N.length != 0) || (S != null && S.length != 0)) {
            this.ext = true; // cSHAKE instead of SHAKE
            byte[] prefix = bytepad(concat(encode_string(N), encode_string(S)), 136);
            update(prefix, prefix.length);
        }
    }
    private static byte[] encode_string(byte[] S) {
        // Validity Conditions: 0 鈮� len(S) < 2^2040
        int slen = (S != null) ? S.length : 0;
        byte[] lenS = (S != null) ? left_encode(slen << 3) : theLeftEncode;; // NB: bitlength, not bytelength
        byte[] encS = new byte[lenS.length + slen];
        System.arraycopy(lenS, 0, encS, 0, lenS.length);
        System.arraycopy((S != null) ? S : encS, 0, encS, lenS.length, slen);
        return encS; // left_encode(len(S)) || S.
    }

   
//    private static byte[] bytepad(byte[] X, int w) {
//
//        byte[] wenc = left_encode(w);
//        byte[] result = new byte[w*((wenc.length + X.length + w - 1)/w)];
//	
//        
//    	return result; 
//    }
    private static byte[] bytepad(byte[] X, int w) {
        // Validity Conditions: w > 0
        // 1. z = left_encode(w) || X.
        byte[] wenc = left_encode(w);
        byte[] z = new byte[w*((wenc.length + X.length + w - 1)/w)]; // z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
        // 2. len(z) mod 8 = 0 (byte-oriented implementation)
        // 3. while (len(z)/8) mod w 鈮� 0: z = z || 00000000
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte)0;
        }
        return z;
    }
    
    
    public void kinit256(byte[] K, byte[] S) {
        // Validity Conditions: len(K) < 2^2040 and len(S) < 2^2040
        byte[] encK = bytepad(encode_string(K), 136);
        cinit256(KMAC_N, S);
        this.kmac = true;
        update(encK, encK.length);
    }

    static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        // Validity Conditions: len(K) < 2^2040 and 0 鈮� L and len(S) < 2^2040
        if ((L & 7) != 0) {
            throw new RuntimeException("Implementation restriction: output length (in bits) must be a multiple of 8");
        }
        byte[] val = new byte[L >>> 3];
        Shake shake = new Shake();
        shake.kinit256(K, S);
        shake.update(X, X.length);
        shake.xof();
        shake.out(val, L >>> 3);
        return val; // SHAKE256(X, L) or KECCAK512(prefix || X || 00, L)
    }

    public static byte[] addPadding(byte[] arr, int size) {
        byte[] result = new byte[arr.length + size - arr.length % size];
        for (int i = 0; i < arr.length; i++) {
            result[i] = arr[i];
        }
        if (size - arr.length % size == 1) { //case: only one char to pad
            result[result.length - 1] = (byte) 0x01; //length - 1 to prevent off-by-one error
        } else { //case: append one and then loop zeroes onto the end until we reach the end
            result[arr.length] = (byte) 0x01; //array.length is the index number of the first new value
            for (int i = arr.length + 1; i < result.length; i++) {
                result[i] = (byte) 0x00; //append zero in every index to the end of the new array for padding.
            }
        }
        return result;
    }
}