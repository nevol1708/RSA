import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

public class RSAKeyGen {
	private KeyPairGenerator keyGen;
	private KeyPair keyPair;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	
	//	3.1 Sinh bộ khóa theo thuật toán RSA
	public RSAKeyGen(int keysize) throws NoSuchAlgorithmException {
		keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(keysize);
		// sinh cặp khóa
		keyPair = keyGen.generateKeyPair();
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();	
	}
	
	//	3.2 Lưu bộ khóa ra file
	public void writeKeyToFile(String path) throws IOException {
		File fpub = new File(path + "PublicKey");
		File fpri = new File(path + "PrivateKey");
		FileOutputStream fos = new FileOutputStream(fpub);
		fos.write(publicKey.getEncoded());
		fos.flush();
		fos.close();
		fos = new FileOutputStream(fpri);
		fos.write(privateKey.getEncoded());
		fos.flush();
		fos.close();
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
		RSAKeyGen rsa = new RSAKeyGen(1024);
		rsa.writeKeyToFile("D:/");
		System.out.println("Key generated");
	}
}
