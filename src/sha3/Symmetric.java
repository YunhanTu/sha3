package sha3;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Symmetric {
	
	private static byte[] theZ = new byte[512];
	private static byte[] theC;
    private static byte[] theT;
    private static String inFileName = "abc.txt";
	private static SecureRandom theRandom;
	
	public Symmetric() {
		 
    }
	
	/*
	 *     z  Random(512)
		▪ (ke || ka)  KMACXOF256(z || pw, “”, 1024, “S”)
		▪ c  KMACXOF256(ke, “”, |m|, “SKE”)  m
		▪ t  KMACXOF256(ka, m, 512, “SKA”)
		▪ symmetric cryptogram: (z, c, t)
	 */
	public static  void encrypt() {
		theRandom = new SecureRandom();
		theRandom.nextBytes(theZ);
		
		@SuppressWarnings("resource")
		Scanner input = new Scanner(System.in);
		System.out.println("Insert Passphrase for Encryption:");
		String pass = input.next();
		
		try { 
			File filename = new File(inFileName); 
			InputStreamReader reader = new InputStreamReader(
					new FileInputStream(filename)); 
			@SuppressWarnings("resource")
			BufferedReader br = new BufferedReader(reader); 
			String line = "";		
			line = br.readLine();
//			System.out.println(line);	
			byte[] key = concat(theZ, pass.getBytes());
			byte[] keka = Shake.KMACXOF256(key, "".getBytes(), 1024, "S".getBytes());
	        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
	        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
	        byte[] m = Shake.addPadding(line.getBytes(), 8);
	        byte[] c = Shake.KMACXOF256(ke, "".getBytes(), m.length, "SKE".getBytes());
	        String cHex = bytesToHex(c);
	        BigInteger cBigInt = new BigInteger(cHex, 16);
	        String mHex = bytesToHex(m);
	        BigInteger mBigInt = new BigInteger(mHex, 16);
	        cBigInt = cBigInt.xor(mBigInt);
	        theC = cBigInt.toByteArray();
	        theT = Shake.KMACXOF256(ka, pass.getBytes(), 512, "SKA".getBytes()); 
	        symmetriccryptogram(theZ,theC,theT);
	        
		} catch (Exception e) {
			e.printStackTrace();
		}

       
	}
	
	public static  void symmetriccryptogram(byte[] Z, byte[] C, byte[] T) {
		PrintStream output = null;
		boolean FilesOk = false;
//		System.out.println();
//		byte[] result1,result2;
//	    result1 = Shake.concat(Z,C);
//	    result2 = Shake.concat(result1, T);
//	    System.out.println("result: " + Symmetric.bytesToHex(result2));
	    try {
			output = new PrintStream(new File ("encrypt.txt"));
			FilesOk = true;
			
		}
		catch(FileNotFoundException e) {
			System.out.println("Can't open file " );
		}
	    if(FilesOk) {
//	    	output.println(bytesToHex(T));
	    	output.close();
	    }
	}
	
	/*
	 *  ▪ (ke || ka)  KMACXOF256(z || pw, “”, 1024, “S”)
		▪ m  KMACXOF256(ke, “”, |c|, “SKE”)  c
		▪ t’  KMACXOF256(ka, m, 512, “SKA”)
		▪ accept if, and only if, t’ = t
	 */
	public static void decrypt() {
		@SuppressWarnings("resource")
		Scanner input = new Scanner(System.in);
		System.out.println("Insert Passphrase for Encryption:");
		String pass = input.next();
		

		try { 
			
			File filename = new File("encrypt.txt"); 
			InputStreamReader reader = new InputStreamReader(
					new FileInputStream(filename)); 
			@SuppressWarnings("resource")
			BufferedReader br = new BufferedReader(reader); 
			String line = "";		
			line = br.readLine();
//			System.out.println(line);
			byte[] key = concat(theZ, ToByteArray(pass)); 
			byte[] keka = Shake.KMACXOF256(key, "".getBytes(), 1024, "S".getBytes());
	        byte[] ke = Arrays.copyOfRange(keka, 0, keka.length / 2);
	        byte[] ka = Arrays.copyOfRange(keka, keka.length / 2, keka.length);
	        
	        byte[] m = Shake.KMACXOF256(ke, "".getBytes(), theC.length, "SKE".getBytes());
	        
	        String mHex = bytesToHex(m);
	        BigInteger mBigInt = new BigInteger(mHex, 16);
	        String cHex = bytesToHex(theC);
	    
	        BigInteger cBigInt = new BigInteger(cHex, 16);
	        mBigInt = mBigInt.xor(cBigInt);
	        m = mBigInt.toByteArray();
	        @SuppressWarnings("unused")
			byte[] Tprime = Shake.KMACXOF256(ka, m, 512, "SKA".getBytes());
	      // String tHex = bytesToHex(theT);
	      // String TprimeHex = bytesToHex(Tprime);
	        byte[] originalM = RemovePadding(m);
	        symmetricdecrypt(originalM);

		} catch (Exception e) {
			System.out.println("Error, no file ");
			e.printStackTrace();
		}
		
		

	}
	
	
	
	public static void symmetricdecrypt(byte[] m) throws UnsupportedEncodingException {
		PrintStream output = null;
		boolean FilesOk = false;
		String s = new String(m,"UTF-8");
		 try {
				output = new PrintStream(new File ("decrpt.txt"));
				FilesOk = true;
				
			}
			catch(FileNotFoundException e) {
				System.out.println("Can't open file  " );
			}
		    if(FilesOk) {
//		    	System.out.println(s);
		    	output.println(s);
		    }
		
	}
	public static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
	public static byte[] ToByteArray(String s) {
		int len = s.length(); // Length of the string
		  byte[] dataset = new byte[len];
		  for (int i = 0; i < len; ++i) {
		     char c = s.charAt(i);
		     dataset[i]= (byte) c;
		  }
        return dataset;
    }
	public static byte[] concat(byte[] a, byte[] b) {
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
	  public static byte[] RemovePadding(byte[] array) {
	        boolean done = false;
	        int i = array.length - 1;
	        int paddingStartIndex = 0;

	        while (!done) {
	            if (array[i] == (byte)0x00) {
	                i--;
	            } else if (array[i] == (byte)0x01) {
	                paddingStartIndex = i;
	                done = true;
	            } else {
	                throw new RuntimeException("Input array is not NIST padded");
	            }
	        }

	        byte[] unpaddedArray = new byte[paddingStartIndex];

	        for (int j = 0; j < paddingStartIndex; j++) {
	            unpaddedArray[j] = array[j];
	        }

	        return unpaddedArray;
	    }

}
