import javax.crypto.Cipher;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;

//Server started with java Server port -- Need to take in a port for starting the socket on
//Server is assumed to have its own private key and all public keys of the users (client)
public class Server {
    static HashMap<String, List<byte[]>> messages = new HashMap<>();

    public static void main(String[] args) throws Exception {

        //Ensure the java file is appropriately launched
        if (args.length != 1) {
            System.out.println("Run with java Server port");
            System.exit(1);
        }

        int port = Integer.parseInt(args[0]);

        System.out.println("Server Program");

        //Create a new server socket for a connection based on port provided
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Sever started at: " + port);

        try {
            //Leave server running continuously
            while (true) {
                Socket client = serverSocket.accept();

                clientConnect(client);

                client.close();

            }
        } finally {
            serverSocket.close();
        }
    }

    private static void clientConnect(Socket client) throws Exception {
        //Creating Input/Output providers
        DataInputStream dis = new DataInputStream(client.getInputStream());
        DataOutputStream dos = new DataOutputStream(client.getOutputStream());

        //Receive userId when client connection starts
        String userId = dis.readUTF();
        System.out.println("Login from user: " + userId);

        List<byte[]> userMessages = messages.get(userId);

        //Print any messages stored in hashmap for that hashed userId
        if (userMessages != null) {
            //Number of messages associated with userId
            int userMessagesLength = userMessages.size();
            //Send number of messages for the user
            dos.writeInt(userMessagesLength);

            for (byte[] encryptedMessage : userMessages) {
                dos.writeInt(encryptedMessage.length);
                dos.write(encryptedMessage);
                dos.flush();
            }
            messages.remove(userId);
        } else {
            dos.writeInt(0);
        }

        String sendMessage = dis.readUTF();

        if (sendMessage.equals("y")) {
            //Receive Encrypted Message -- Stored in encrypted message
            int length = dis.readInt();
            byte[] encryptedMessage = new byte[length];
            dis.readFully(encryptedMessage);

            decryptEncryptRecipient(encryptedMessage);
        }

        //Send message immediately
        dos.flush();

        //Close the I/O Providers
        dis.close();
        dos.close();

    }

    private static byte[] decryptEncryptRecipient(byte[] encryptedMessage) throws Exception {
        //Use server private key for decryption
        File serverPrv = new File("Keys/server.prv");
        byte[] serverKeyBytes = Files.readAllBytes(serverPrv.toPath());
        PKCS8EncodedKeySpec serverPubSpec = new PKCS8EncodedKeySpec(serverKeyBytes);
        KeyFactory serverKF = KeyFactory.getInstance("RSA");
        PrivateKey serverPrvKey = serverKF.generatePrivate(serverPubSpec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, serverPrvKey);
        byte[] raw = cipher.doFinal(encryptedMessage);
        String decryptedMessage = new String(raw, "UTF8");
        System.out.println("Raw Decrypted Message test: " + decryptedMessage);

        String[] split = decryptedMessage.split(",");

        String senderUserId = split[0];
        String recipientUserId = split[1];
        String message = split[2];

        String hashedRecUserId = hashUserId(recipientUserId);

        //Re-encrypt message with recipient public key
        File recPub = new File("Keys/" + recipientUserId + ".pub");
        byte[] recKeyBytes = Files.readAllBytes(recPub.toPath());
        X509EncodedKeySpec recPubSpec = new X509EncodedKeySpec(recKeyBytes);
        KeyFactory recKF = KeyFactory.getInstance("RSA");
        PublicKey recPubKey = recKF.generatePublic(recPubSpec);

        Cipher recCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        recCipher.init(Cipher.ENCRYPT_MODE, recPubKey);
        byte[] recRaw = recCipher.doFinal(message.getBytes("UTF8"));

        //Testing the output
        String recEncryptedMessage = new String(recRaw, "UTF8");
        System.out.println("Re-encrypted Message: " + recEncryptedMessage);

        //Calling method to store the re-encrypted message with the recipient's user id
        messagesStore(hashUserId(recipientUserId), recRaw);

        return recRaw;

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

    public static void messagesStore(String hashedUserId, byte[] encryptedMessage) {

        //Storing message in or creating a new hashmap with the users hashed id and their messages
        if (messages.containsKey(hashedUserId)) {
            List<byte[]> messageList = messages.get(hashedUserId);
            messageList.add(encryptedMessage);
            messages.put(hashedUserId, messageList);
        } else {
            List<byte[]> messageList = new ArrayList<>();
            messageList.add(encryptedMessage);
            messages.put(hashedUserId, messageList);
        }
    }

    private static byte[] generateSignature(byte[] encryptedMessage, Date timestamp) throws Exception {
        File f = new File("Keys/server.prv");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        PKCS8EncodedKeySpec serverPrvSpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey serverPrvKey = kf.generatePrivate(serverPrvSpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(serverPrvKey);
        sig.update(encryptedMessage);
        sig.update(timestamp.toString().getBytes());
        byte[] signature = sig.sign();

        return signature;
    }

    private static boolean checkSignature(byte[] encryptedMessage, String timestamp, byte[] signature, String senderUserId) throws Exception {
        File f = new File("Keys/" + senderUserId + ".pub");
        byte[] keyBytes = Files.readAllBytes(f.toPath());
        X509EncodedKeySpec clientPubSpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey clientPubKey = kf.generatePublic(clientPubSpec);

        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(clientPubKey);
        sig.update(encryptedMessage);
        sig.update(timestamp.getBytes());
        boolean check = sig.verify(signature);

        return check;
    }

}
