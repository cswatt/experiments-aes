/*
 * Cecilia Saixue Watt (ciw2104)
 */
import java.net.*;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Client1{
	static byte[] key;
    static byte[] initialization_vector;
    
   public static void main(String [] args) throws IOException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException {
      //check that arguments are valid
      if (!checkArgs(args)) return;
      
      Socket client = null;
      String serverName = args[0];
      int port = Integer.parseInt(args[1]);
      String filename = args[2];
      String password = args[3];
      String mykey_private = args[4];
      String theirkey_public = args[5];
      
      try{
         System.out.println("Connecting to " + serverName + " on port " + port);
         client = new Socket(serverName, port);
         System.out.println("Just connected to " + client.getRemoteSocketAddress());
         
         //load the file to send
         byte [] plaintext = loadFile(filename);
         
         //encrypt plaintext
         byte [] ciphertext = AES_encrypt(plaintext, password);
         
         //load client2's publickey
         PublicKey pub2 = loadPublic(theirkey_public);
         
         //encrypt aes key with client 2 public key
         byte[] encryptedkey = RSA_encrypt(key, pub2);
         
         //load client 1's privatekey
         PrivateKey priv1 = loadPrivate(mykey_private);
         
         //create signature
         byte[] signature = RSA_encrypt(SHA_256(plaintext), priv1);
         
         //send data to server
         DataOutputStream outToServer = new DataOutputStream(client.getOutputStream());
         outToServer.write(encryptedkey, 0, 256);
         outToServer.write(signature, 0, 256);
         outToServer.write(initialization_vector, 0, 16);
         outToServer.writeInt(ciphertext.length);
         outToServer.write(ciphertext,0,ciphertext.length);
         
         outToServer.flush();
         
         System.out.println("Messages sent. Goodbye.");
      } catch (ConnectException e) {
    	System.out.println("Couldn't connect to server...");
      } catch (FileNotFoundException e) {
    	System.out.println("One of your files doesn't exist.");
      } catch(IOException e){
        e.printStackTrace();
      } catch (IllegalBlockSizeException e) {
		e.printStackTrace();
      } catch (InvalidKeySpecException e) {
		System.out.println("One or more RSA files are invalid and cannot be loaded.");
	} 
   }
   public static boolean checkArgs(String [] args) {
	   //a method for checking that nothing is wrong with the command line args
	   boolean isValid = true;
	   if (args.length < 6){
		   System.out.println("Did not supply enough arguments");
		   System.out.println("ARGUMENTS: [name] [port number] [filename] [password] [your private key] [other guys' public key] ");
		   return false;
	   }
	   if (!args[1].matches("[0-9]+")){
		   System.out.println("Invalid port number. Port number can only contain numbers.");
		   return false;
	   }
	   if (!args[3].matches("[0-9A-Za-z.,/<>?;:\'\"{}\\[\\]\\|!@#$%^&*()-=+_]+")){
		   System.out.println("Password contains illegal characters.");
		   return false;
	   }
	   if (args[3].length() != 16){
			System.out.println("Password is not correct length. Password must be 16 chars.");
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
   
   public static byte[] AES_encrypt(byte[] input, String password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
       /*
        * given input of plaintext as byte[], password as String
        * creates a SecretKey and Cipher, encrypts the plaintext
        * updates global vectors key and initialization_vector
        * returns ciphertext as byte[]
        */
	   SecretKey sk = new SecretKeySpec(password.getBytes(), 0, 16, "AES");
       Cipher cipherOut = Cipher.getInstance("AES/CBC/PKCS5Padding");
       cipherOut.init(Cipher.ENCRYPT_MODE, sk);
       byte [] output = cipherOut.doFinal(input);
       key = sk.getEncoded();
       initialization_vector = cipherOut.getIV();
       return output;
   }
   
   public static byte[] RSA_encrypt(byte[] input, PublicKey publickey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
	   /*
	    * given input of plaintext as byte[], and a public key
	    * encrypts using RSA and returns ciphertext
	    */
	   Cipher cipherOut = Cipher.getInstance("RSA");
	   cipherOut.init(Cipher.ENCRYPT_MODE, publickey);
	   byte[] output = cipherOut.doFinal(input);
	   return output;
   }
   
   public static byte[] RSA_encrypt(byte[] input, PrivateKey privatekey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
	   /*
	    * given input of plaintext as byte[], and a private key
	    * encrypts using RSA and returns ciphertext
	    */
	   Cipher cipherOut = Cipher.getInstance("RSA");
	   cipherOut.init(Cipher.ENCRYPT_MODE, privatekey);
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