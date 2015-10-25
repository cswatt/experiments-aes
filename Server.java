/*
 * Cecilia Saixue Watt (ciw2104)
 */
import java.net.*;
import java.io.*;

public class Server extends Thread{
	private ServerSocket serverSocket;
	static boolean isTrusted = true;

	public Server(int port) throws IOException{
		serverSocket = new ServerSocket(port);
		serverSocket.setSoTimeout(10000);
	}

	public void run(){
		boolean hasRead = false;
		byte[] key = new byte [256];
		byte[] signature = new byte[256];
		byte[] initialization_vector = new byte [16];
		byte[] ciphertext = new byte [1048576];
		int text_length = 0;
		while(true){
			try{
				System.out.println("Waiting on port " + serverSocket.getLocalPort() + "...");
				Socket server = serverSocket.accept();           
				System.out.println("I have connected to " + server.getRemoteSocketAddress() + "!");

				if (hasRead){
					//start sending
					DataOutputStream outToClient2 = new DataOutputStream(server.getOutputStream());
					outToClient2.write(key,0,256);
					outToClient2.write(signature,0,256);
					outToClient2.write(initialization_vector,0,16);
					if (isTrusted){
						outToClient2.writeInt(text_length);
						outToClient2.write(ciphertext,0,text_length);
					}
					else{
						byte[] fakefile = loadFile("serverdata");
						outToClient2.writeInt(fakefile.length);
						outToClient2.write(fakefile,0,fakefile.length);
					}

					System.out.println("I have sent files to " + server.getRemoteSocketAddress() + ".");

					//enter into RECEIVING STATE
					outToClient2.close();
					hasRead = false;
				}

				else {
					//server in RECEIVING STATE
					DataInputStream inFromClient1 = new DataInputStream(server.getInputStream());
					inFromClient1.read(key,0,256);
					inFromClient1.read(signature,0,256);
					inFromClient1.read(initialization_vector,0,16);

					//get file length and read file
					text_length = inFromClient1.readInt();
					inFromClient1.read(ciphertext,0,text_length);

					System.out.println("I have received files from " + server.getRemoteSocketAddress() + ".");
					//enter into SENDING STATE
					inFromClient1.close();
					hasRead = true;
				}
				server.close();
			} catch(SocketTimeoutException s){
				System.out.println("Socket timeout!");
				break;
			} catch(EOFException e){
				System.out.println("The client sent us bad input. Exiting.");
				break;
			} catch(IOException e){
				e.printStackTrace();
				break;
			}
		}
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

	public static boolean checkArgs(String[] args){
		//check that arguments are valid
		boolean isValid = true;
		if (args.length < 2){
			System.out.println("Did not supply enough arguments.");
			System.out.println("ARGUMENTS: [port number] [mode]");
			return false;
		}
		if (!args[0].matches("[0-9]+")){
			System.out.println("Invalid port number. Port number can only contain numbers.");
			return false;
		}
		char mode = args[1].charAt(0);
		if (mode=='t'|| mode=='T') {
			isTrusted = true;
		} else if (mode=='u' || mode=='U'){
			isTrusted = false;
		} else {
			System.out.println("Did not supply valid mode. Mode can only be t or u.");
			return false;
		}
		return isValid;
	}

	public static void main(String [] args){
		if (!checkArgs(args)) return;
		int port = Integer.parseInt(args[0]);

		//I HAVE NO IDEA WHAT I'M DOING WITH THREADS
		try{
			Thread t = new Server(port);
			t.start();
		}catch(IOException e){
			e.printStackTrace();
		}
	}
}
