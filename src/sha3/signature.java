package sha3;

public class signature {
	

	/*
	 * Generating a signature σ for a byte array m under the passphrase pw:
		▪ s  KMACXOF256(pw, “”, 512, “K”); s  4s
		▪ k  KMACXOF256(s, m, 512, “N”); k  4k
		▪ U  k*G;
		▪ h  KMACXOF256(Ux, m, 512, “T”); z  (k – hs) mod r
		▪ σ  (h, z)

	 */
	public static void generS() {
		
	}

}
