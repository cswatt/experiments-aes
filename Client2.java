/*
 * Cecilia Saixue Watt (ciw2104)
 */
import java.net.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Client2{
	public static void main(String [] args) {
		//check that arguments are valid
		if(!checkArgs(args)) return;
		String serverName = args[0];
		int port = Integer.parseInt(args[1]);
		String mykey_private = args[2];
		String theirkey_public = args[3];

		try{
			System.out.println("Connecting to " + serverName + " on port " + port);
			Socket client = new Socket(serverName, port);
			System.out.println("Just connected to " + client.getRemoteSocketAddress());

			//get data from server
			DataInputStream inFromServer = new DataInputStream(client.getInputStream());
			byte[] key = new byte [256];
			inFromServer.read(key,0,256);
			byte[] signature = new byte [256];
			inFromServer.read(signature,0,256);
			byte[] initialization_vector = new byte [16];
			inFromServer.read(initialization_vector,0,16);
			int text_length = inFromServer.readInt();
			byte[] ciphertext = new byte [text_length];
			inFromServer.read(ciphertext,0,text_length);

			System.out.println("Messages received.");

			//load privatekey from file
			PrivateKey priv = loadPrivate(mykey_private);

			//decrypt aes key
			byte[] decryptedkey = RSA_decrypt(key, priv);

			//decrypt plaintext
			byte[] plaintext = AES_decrypt(ciphertext, decryptedkey, initialization_vector);

			//load client 1's publickey from file
			PublicKey pub = loadPublic(theirkey_public);

			//decrypt signature
			byte[] decryptedsig = RSA_decrypt(signature, pub);

			//check verification
			if(Arrays.equals(decryptedsig, SHA_256(plaintext))){
				System.out.println("VERIFICATION PASSED");
				FileOutputStream fos = new FileOutputStream("client2data");
				BufferedOutputStream bos = new BufferedOutputStream(fos);
				bos.write(plaintext, 0, plaintext.length);
				bos.close();
				fos.close();
			}
			else {
				System.out.println("VERIFICATION FAILED");
			}

			client.close();
		} catch (ConnectException e) {
			System.out.println("Couldn't connect to server...");
		} catch (FileNotFoundException e) {
			System.out.println("One of your files doesn't exist.");
		} catch(EOFException e){
			System.out.println("The server sent us bad input.");
		} catch(IOException e){
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			System.out.println("The AES key is not valid.");
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			System.out.println("VERIFICATION FAILED");
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			System.out.println("One or more RSA files are invalid and cannot be loaded.");
		} 
	}

	public static boolean checkArgs(String[] args){
		//a method for checking that nothing is wrong with the command line args
		boolean isValid = true;
		if (args.length < 4){
			System.out.println("Did not supply enough arguments");
			System.out.println("ARGUMENTS: [name] [port number] [your private key] [other guy's public key]");
			return false;
		}
		if (!args[1].matches("[0-9]+")){
			System.out.println("Invalid port number. Port number can only contain numbers.");
			return false;
		}
		return isValid;
	}
	public static byte[] loadFile(String filename) throws IOException{
		//given a string filename, loads file into byte[]
		File myFile = new File(filename);
		byte [] output = new byte [(int)myFile.length()];
		FileInputStream fis = new FileInputStream(myFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		bis.read(output,0,output.length);
		bis.close();
		fis.close();
		return output;
	}
	public static byte[] AES_decrypt(byte[] input, byte[] key, byte[] initVector) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		/*
		 * given input of ciphertext as byte[], key as byte[], IV as byte[]
		 * creates a cipher object
		 * creates a SecretKey object from key
		 * creates an IvParamterSpec object from iv
		 * decrypts ciphertext using key and iv
		 */
		Cipher myCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKey k = new SecretKeySpec(key, 0, key.length, "AES");
		IvParameterSpec iv = new IvParameterSpec(initVector);
		myCipher.init(Cipher.DECRYPT_MODE, k, iv);
		byte[] output = myCipher.doFinal(input);
		return output;
	}

	public static byte[] RSA_decrypt(byte[] input, PublicKey publickey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		/*
		 * decrypts ciphertext using public key
		 */
		Cipher cipherOut = Cipher.getInstance("RSA");
		cipherOut.init(Cipher.DECRYPT_MODE, publickey);
		byte[] output = cipherOut.doFinal(input);
		return output;
	}

	public static byte[] RSA_decrypt(byte[] input, PrivateKey privatekey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
		/*
		 * decrypts ciphertext using private key
		 */
		Cipher cipherOut = Cipher.getInstance("RSA");
		cipherOut.init(Cipher.DECRYPT_MODE, privatekey);
		byte[] output = cipherOut.doFinal(input);
		return output;
	}

	public static byte[] SHA_256(byte[] input) throws NoSuchAlgorithmException{
		/*
		 * given input of plaintext as byte[], hashes using SHA-256
		 */
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		md.update(input);
		byte[] output = md.digest();
		return output;
	}

	public static PrivateKey loadPrivate(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		/*
		 * loads a private key file
		 */

		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(loadFile(keyfile));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public static PublicKey loadPublic(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException{
		/*
		 * loads a public key file
		 */

		X509EncodedKeySpec spec = new X509EncodedKeySpec(loadFile(keyfile));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}
}