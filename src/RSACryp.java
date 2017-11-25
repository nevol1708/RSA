import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSACryp {
	private PublicKey publicKey;
	private PrivateKey privateKey;

	public PrivateKey getPrivateKey() {
		return privateKey;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	// 3.3 Hàm đọc file để nạp khóa bí mật, tham số truyền vào là tên file
	public PrivateKey readPrivateKeyFromFile(String path)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		File f = new File(path);
		byte[] encodedprivate = Files.readAllBytes(f.toPath());
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedprivate);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		privateKey = kf.generatePrivate(keySpec);
		return privateKey;
	}

	// 3.4 Hàm đọc file để nạp khóa công khai, tham số truyền vào là tên file
	public PublicKey readPublicKeyFromFile(String path)
			throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
		File f = new File(path);
		byte[] encodedpublic = Files.readAllBytes(f.toPath());
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedpublic);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		publicKey = kf.generatePublic(keySpec);
		return publicKey;
	}

	// 3.5 Hàm mã hóa một thông điệp cho trước bằng khóa bí mật, tham số truyền vào
	// gồm tham số thứ nhất là thông điệp cần mã hóa, tham số thứ 2 là khóa bí mật
	public String encryptText(String msg, PrivateKey key) throws IllegalBlockSizeException, BadPaddingException,
			UnsupportedEncodingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return Base64.getEncoder().encodeToString(cipher.doFinal(msg.getBytes("UTF-8")));
	}

	// 3.6 Hàm giải mã thông điệp bằng khóa công khai, tham số truyền vào gồm tham
	// số thứ nhất là bản mã cần giải mã, tham số thứ 2 là khóa công khai.
	public String decryptText(String msg, PublicKey key) throws UnsupportedEncodingException, IllegalBlockSizeException,
			BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, key);
		String decrypted = new String(cipher.doFinal(Base64.getDecoder().decode(msg)), "UTF-8");
		return decrypted;
	}

	public static void main(String[] args) throws InvalidKeySpecException, NoSuchAlgorithmException, IOException,
			InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchPaddingException {

		// 3.7 Sử dụng lớp RSACryp để mã hóa một chuỗi và băm chuỗi theo một thuật toán
		// băm cho trước rồi lưu cả bản mã và bản băm vào một file
		String msg = "Dữ liệu cần mã hóa";
		RSACryp rsa = new RSACryp();
		Digest digest = new Digest();
		rsa.readPrivateKeyFromFile("D:/PrivateKey");
		rsa.readPublicKeyFromFile("D:/PublicKey");
		System.out.println("Plain Text: " + msg);
		String encrypted = rsa.encryptText(msg, rsa.getPrivateKey());
		System.out.println("Encrypted Text: " + encrypted);
		//	lưu bản mã vào file
		File encryptedMesage = new File("D:/EncryptedMessage");
		encryptedMesage.createNewFile();
		FileWriter fw = new FileWriter(encryptedMesage, false);
		BufferedWriter out = new BufferedWriter(fw);
		out.write(encrypted);
		out.newLine();
		out.flush();
		//	băm bản rõ
		System.out.println("Choose digest method:");
		System.out.println("1. MD5, 2. SHA-1, 3. SHA-256");
		Scanner scanner = new Scanner(System.in);
		int choose = scanner.nextInt();
		//	lưu bản băm vào file
		String digestmsg = "";
		if (choose == 1) {
			digestmsg = digest.md5Digest(msg);
			System.out.println("MD5 digest: " + digestmsg);
			out.write(digestmsg);
		}
		else if (choose == 2) {
			digestmsg = digest.sha1Digest(msg);
			System.out.println("SHA-1 digest: " + digestmsg);
			out.write(digestmsg);
		}
		else if (choose == 3) {
			digestmsg = digest.sha256Digest(msg);
			System.out.println("SHA-256 digest: " + digestmsg);
			out.write(digestmsg);
		}
		out.flush();
		out.close();
		// 3.8 Đọc file chứa bản mã và bản băm của một thông điệp, sử dụng lớp RSACryp
		// để giải mã ra thông điệp gốc và băm lại bằng thuật toán băm cho trước. Sau đó
		// đem so sánh hai bản băm để xác nhận tính toàn vẹn
		BufferedReader br = new BufferedReader(new FileReader(encryptedMesage));
		String encryptedmsg = br.readLine();
		System.out.println("Encrypted Text From File: " + encryptedmsg);
		String digestedmsg = br.readLine();
		String decrypted = rsa.decryptText(encryptedmsg, rsa.getPublicKey());
		System.out.println("Decrypted Text From File: " + decrypted);
		// băm lại bản rõ
		String digestdecypt ="";
		if (choose == 1) {
			digestdecypt = digest.md5Digest(decrypted);
			System.out.println("MD5 digest of Decrypted: " + digestdecypt);
		}
		else if (choose == 2) {
			digestdecypt = digest.sha1Digest(decrypted);
			System.out.println("SHA-1 digest of Decrypted: " + digestdecypt);
		}
		else if (choose == 3) {
			digestdecypt = digest.sha256Digest(decrypted);
			System.out.println("SHA-256 digest of Decrypted: " + digestdecypt);
		}
		//	so sánh hai bản băm để xác nhận tính toàn vẹn
		if(digestdecypt.equals(digestedmsg))
			System.out.println("Data Match");
		else
			System.out.println("Data Un-Match");
	}

}
