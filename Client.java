import javax.crypto.Cipher;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.Date;
import java.util.Scanner;

//Client started with java Client host (of server) port (of server) userid (alice, bob, etc.)
//Client is assumed to have their own private key and the public key of the server
public class Client {

    public static void main(String[] args) throws Exception {

        //Ensure the java file is appropriately launched
        if (args.length != 3) {
            System.out.println("Run with java Client host port userid");
            System.exit(1);
        }

        //Create a new connection store host/port and the user's id
        String host = args[0];
        int port = Integer.parseInt(args[1]);
        String userId = args[2];

        //Create a new server socket based on provided arguments
        Socket socket = new Socket(host, port);

        //Debug statement
        System.out.println("Client Program (user " + userId +")");

        //Create Input/Output providers
        DataInputStream dis = new DataInputStream(socket.getInputStream());
        DataOutputStream dos = new DataOutputStream(socket.getOutputStream());

        //Send userId for testing to the server
        dos.writeUTF(hashUserId(userId));

        //Reading in any messages sent by server (SAMPLE CODE COPIED FROM SERVER)

        int messagesForUserLength = dis.readInt();
        System.out.println("You have " + messagesForUserLength + " messages:");
        for (int i = 0; i < messagesForUserLength; i++) {
            int length = dis.readInt();
            if (length > 0) {
                byte[] encryptedMessageIn = new byte[length];
                dis.readFully(encryptedMessageIn);
                System.out.println("Message: " + decryptMessage(encryptedMessageIn, userId));
            }
        }

        System.out.println("Do you want to send a message? (y/n): ");
        Scanner sendMessageInput = new Scanner(System.in);
        String sendMessage = sendMessageInput.nextLine().toLowerCase();

        dos.writeUTF(sendMessage);

        if (sendMessage.equals("y")) {
            System.out.println("Enter message: ");
            Scanner messageInput = new Scanner(System.in);
            String message = messageInput.nextLine();

            System.out.println("Enter the user id of the recipient: ");
            Scanner recipientInput = new Scanner(System.in);
            String recUserId = recipientInput.nextLine();

            String messageSendRec = userId + "," + recUserId + "," + message;

            String encryptedUserId = hashUserId(userId);
            Date timestamp = new Date();

            //Encrypt the message (senderUserId, recipientUserId, message content) with server public key
            byte[] encryptedMessage = hashMessage(messageSendRec, timestamp);


            //Send encrypted message bytes to server
            dos.writeInt(encryptedMessage.length);
            dos.write(encryptedMessage);

        }

        //Close socket and I/O providers
        dis.close();
        dos.close();
        socket.close();

    }

    private static String hashUserId(String userId) throws NoSuchAlgorithmException {

        String userIdPrepend = "gfhk2024:";
        byte[] userIdPreHash = (userIdPrepend + userId).getBytes();

        MessageDigest md = MessageDigest.getInstance("MD5");
        //Add the userId and prepend to the MessageDigest
        md.update(userIdPreHash);

        byte[] userIdDigest = md.digest();

        //Converting Bytes to Hexadecimal --> https://mkyong.com/java/java-how-to-convert-bytes-to-hex/
        StringBuilder userIdHex = new StringBuilder();
        for (byte b : userIdDigest) {
            userIdHex.append(String.format("%02x", b));
        }

        return userIdHex.toString();
    }

    private static byte[] hashMessage(String message, Date timestamp) throws Exception {
        //Need to encrypt messages with servers public key --> sent to server decrypted --> server encrypts with recipient public --> recipient decrypts with their private
        //Server computes the hashed recipient userId and only uses it to store and locate saved message --> original un-hashed recipient id is discarded
        //Each message also comes with an unencrypted timestamp

        // SAMPLE CODE FROM SERVER.JAVA The code to read the generated key
        File f = new File("Keys/server.pub");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec pubSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey publicKey = kf.generatePublic(pubSpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] raw = cipher.doFinal(message.getBytes("UTF8"));

        return raw;
    }

    private static String decryptMessage(byte[] encryptedMessage, String userId) throws Exception {
        //Taken from example in server file
        File serverPrv = new File("Keys/" + userId + ".prv");
        byte[] serverKeyBytes = Files.readAllBytes(serverPrv.toPath());
        PKCS8EncodedKeySpec serverPubSpec = new PKCS8EncodedKeySpec(serverKeyBytes);
        KeyFactory serverKF = KeyFactory.getInstance("RSA");
        PrivateKey serverPrvKey = serverKF.generatePrivate(serverPubSpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, serverPrvKey);
        byte[] raw = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(raw, "UTF8");
        System.out.println("Raw Decrypted Message test: " + decryptedMessage);

        return decryptedMessage;
    }

    private static byte[] generateSignature(byte[] encryptedMessage, Date timestamp, String userId) throws Exception {
        File f = new File("Keys/" + userId + ".prv");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec clientPrvSpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey clientPrvKey = kf.generatePrivate(clientPrvSpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(clientPrvKey);
        sig.update(encryptedMessage);
        sig.update(timestamp.toString().getBytes());
        byte[] signature = sig.sign();

        return signature;
    }

    private static boolean checkSignature(byte[] encryptedMessage, Date timestamp, byte[] signature) throws Exception {
        File f = new File("Keys/server.pub");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec serverPubSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey serverPubKey = kf.generatePublic(serverPubSpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(serverPubKey);
        sig.update(encryptedMessage);
        sig.update(timestamp.toString().getBytes());
        boolean check = sig.verify(signature);

        return check;
    }
}
