package sha3;


import java.util.Scanner;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;



public class main {
	public static void main(String[] args){
		int flag = 1;
		while(flag != 2) {
			Scanner myScanner = new Scanner(System.in);
			System.out.println("1) Assignment 1: Hash something with SHA3");
			System.out.println("2) Assignment 2: Symmetric Encryption with Passphrase");
			System.out.println("3) Assignment 3: Creating Elliptic key pairs");
			System.out.println("4) Exit");
			int theChoice = myScanner.nextInt();
			if(theChoice == 1) {
				System.out.println("1) Though file");
				System.out.println("2)type in the txt");
				int theChoice2 = myScanner.nextInt();
				if(theChoice2 == 1) {
					try { 
					
						File filename = new File("abc.txt"); 
						InputStreamReader reader = new InputStreamReader(
								new FileInputStream(filename)); 
						BufferedReader br = new BufferedReader(reader); 
						String line = "";		
						line = br.readLine();
						System.out.println(line);
						byte[] result = Shake.KMACXOF256("".getBytes(), line.getBytes(), 512, "D".getBytes());
						System.out.println("KMACXOF256 result: " + Symmetric.bytesToHex(result));	
			 
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
				else {
				
					String c = myScanner.next();
					byte[] result = Shake.KMACXOF256("".getBytes(), c.getBytes(), 512, "D".getBytes());
					System.out.println("KMACXOF256 result: " + Symmetric.bytesToHex(result));	
				}
				
			}
			              	
			else if(theChoice == 2) {
				System.out.println("1) Encrypt a file");
				System.out.println("2) Decrypt a file");
	
				int theChoice3 = myScanner.nextInt();
				if(theChoice3 == 1) {
					Symmetric.encrypt();
				}
				else {
					Symmetric.decrypt();
				}
			}
			else if(theChoice == 3) {
				
			}
			else if(theChoice == 4) {
				flag = 2;
				myScanner.close();
			}
		}
	}

	
	
	
}
