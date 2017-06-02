/**
 * Created by Madeline on 20/01/2017.
 */

package encryptUtils;

import java.io.File;

public class Main {

    public static void main(
            String[] args)
            throws Exception {
        String username = "totoPGP";
        String username2 = "secondUserPGP";
        char[] password = "password".toCharArray();

        //pic.jpg FreeBSD.iso
        File inputFile = new File("pic.jpg");

        String toEncrypt = "Lorem Ipsum is simply dummy text of the printing and typesetting industry. Lorem Ipsum has been the industry's standard dummy text ever since the 1500s, when an unknown printer took a galley of type and scrambled it to make a type specimen book. It has survived not only five centuries, but also the leap into electronic typesetting, remaining essentially unchanged. It was popularised in the 1960s with the release of Letraset sheets containing Lorem Ipsum passages, and more recently with desktop publishing software like Aldus PageMaker including versions of Lorem Ipsum.";
        String smaller = "a small string to test stuff";

        byte[] byte1 = toEncrypt.getBytes();
        byte[] byte2 = smaller.getBytes();
        /*
        *   PGP
        */
//        System.out.println( "----- PGP -----" );
//
//        PGP firstUser = new PGP();
//        PGP secondUser = new PGP();
//
//
//        try {
//            System.out.println("\n----- Generate Key -----");
//            firstUser.generateKeypair(password, username);
//            System.out.println("\n----- Load Key -----");
//            firstUser.loadKeyPair(password, username);
//            firstUser.loadFriendPublicKey(firstUser.getPublicKey());
//
//            System.out.println("\n----- String Encrypt small -----");
//            System.out.println("to encrypt2: " + smaller);
//            String encrypted2 = firstUser.encryptString(smaller);
//            System.out.println("encrypted: " + encrypted2);
//
//            System.out.println("----- String Decrypt small -----");
//            String decrypted2 = firstUser.decryptString(encrypted2);
//            System.out.println("decrypted: " + decrypted2);
//
//            System.out.println("\n----- String Encrypt big -----");
//            System.out.println("to encrypt: " + toEncrypt);
//            String encrypted = firstUser.encryptString(toEncrypt);
//            System.out.println("encrypted: " + encrypted);
//
//            System.out.println("----- String Decrypt big -----");
//            String decrypted = firstUser.decryptString(encrypted);
//            System.out.println("decrypted: " + decrypted);
//
//            System.out.println("\n----- File Encrypt -----");
//            File encryptedFile = firstUser.encryptFile(inputFile.getName());
//            System.out.println( "encryptedFileName: " + encryptedFile.getName());
//
//            System.out.println("----- File Decrypt -----");
//            File decryptedFile = firstUser.decryptFile(encryptedFile.getName());
//            System.out.println( "decryptedFileName: " + decryptedFile.getName());
//
//            System.out.println("----- second user -----");
//            secondUser.generateKeypair(password, username2);
//            secondUser.loadKeyPair(password, username2);
//            secondUser.loadFriendPublicKey(firstUser.getPublicKey());
//            String test = secondUser.encryptString("test d'encryption");
//            String dectest = firstUser.decryptString(test);
//            System.out.println("si ca marche: " + dectest);
//
//        } catch (CryptoException ex) {
//            System.out.println(ex.getMessage());
//            ex.printStackTrace();
//        }

        /*
        *   AES
        */
        System.out.println( "----- AES -----" );

        String userName = "bobAES";

        AES aes = new AES();

        try {
            System.out.println("\n----- Generate Key -----");
            aes.generateKey(password, userName);
            System.out.println("\n----- Load Key -----");
            aes.loadKey(password, userName);

            System.out.println("\n----- File Encryption -----");
            System.out.println("inputFileName: " + inputFile.getName());
            File encryptedFile = aes.encryptFile(inputFile);
            System.out.println( "encryptedFileName: " + encryptedFile.getName());

            System.out.println("----- File Decryption -----");
            File decryptedFile = aes.decryptFile(encryptedFile);
            System.out.println( "decryptedFileName: " + decryptedFile.getName());

            System.out.println("\n----- String Encryption -----");
            byte[]outputBytes = aes.encryptString(toEncrypt);
            System.out.println(new String(outputBytes));

            System.out.println("----- String Decryption -----");
            String decryptedString = aes.decryptString(outputBytes);
            System.out.println(decryptedString);

        } catch (CryptoException ex) {
            System.out.println(ex.getMessage());
            ex.printStackTrace();
        }

        /*
        *   PGP BOUNCY
        */
//        System.out.println( "----- PGPBOUNCY -----" );
//        PGPBouncy pgp = new PGPBouncy();
//
//        //pgp.exportKeyPair(username,password,true);
//        pgp.encryptFile("encrypted", "0.jpg","pub.asc", true, true);
//        pgp.decryptFile("encrypted", "secret.asc", password, "truc");

//        System.out.println(byte2);
//        byte[] encrypted = pgp.encryptByteArray(byte2, "pub.asc", null, true);
//        System.out.println(encrypted);
//        byte[] decrypted = pgp.decryptByteArray(encrypted, "secret.asc", password);
//        System.out.println(decrypted);

        try {
            AES256 _crypt = new AES256();

            String output= "";
            String plainText = toEncrypt;

            String key = AES256.SHA256("my secret key", 32); //32 bytes = 256 bit
            String iv = AES256.generateRandomIV(16); //16 bytes = 128 bit

            System.out.println("\n----- String Encryption -----");
            output = _crypt.encrypt(plainText, key, iv);
            System.out.println(output);

            System.out.println("----- String Decryption -----");
            output = _crypt.decrypt(output, key,iv);
            System.out.println(output);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("\nEnd");
    }
}
