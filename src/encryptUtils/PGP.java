/**
 * Created by Madeline on 15/09/2016.
 */

package encryptUtils;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

public class PGP {
    private static KeyPair userKeyPair = null;
    private static PublicKey friendPublicKey = null;

    private static final int KEY_SIZE = 1024;

    public PGP() {
    }

    /**
     *
     * @param password
     * @param userName
     * @throws CryptoException
     */
    public void generateKeypair(
            char[] password,
            String userName)
            throws CryptoException {
        KeyPairGenerator kpg;
        KeyPair kp;

        try {
            kpg = KeyPairGenerator.getInstance("RSA");
        } catch ( NoSuchAlgorithmException ex) {
            throw new CryptoException("generateKeypair error", ex);
        }

        kpg.initialize(KEY_SIZE);
        kp = kpg.generateKeyPair();
        saveKeyPair(kp, password, userName);
    }

    /**
     *
     * @param keyPair
     * @param password
     * @param userName
     * @throws CryptoException
     */
    private void saveKeyPair(
            KeyPair keyPair,
            char[] password,
            String userName)
            throws CryptoException {
        KeyStore keyStore;

        try {
            //Make method for that
            CertAndKeyGen keyGen = new CertAndKeyGen("RSA","SHA1WithRSA",null);
            keyGen.generate(1024);
            //Generate self signed certificate
            X509Certificate[] chain = new X509Certificate[1];
            chain[0]=keyGen.getSelfCertificate(new X500Name("CN=ROOT"), (long)365*24*3600);
            //Up to that

            keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(null, null);
            keyStore.setKeyEntry(
                    userName + "pe", keyPair.getPrivate(), password, chain);
            keyStore.setKeyEntry(
                    userName + "pc", keyPair.getPublic(), password, null);
            keyStore.store(new FileOutputStream(userName + ".jceks"), password);

            userKeyPair = keyPair;
        } catch (KeyStoreException
                | CertificateException
                | NoSuchAlgorithmException
                | IOException
                | SignatureException
                | NoSuchProviderException
                | InvalidKeyException ex) {
            throw new CryptoException("Error saveKeyPair", ex);
        }
    }

    /**
     *
     * @param password
     * @param userName
     * @return
     * @throws CryptoException
     */
    public  KeyPair loadKeyPair(
            char[] password,
            String userName)
            throws CryptoException {
        KeyStore keyStore;
        KeyPair keyPair;

        try {
            //If file doesn't exist call genKey
            keyStore = KeyStore.getInstance("JCEKS");
            keyStore.load(new FileInputStream(userName + ".jceks"), password);
            keyPair = new KeyPair(
                    (PublicKey) keyStore.getKey(userName + "pc", password),
                    (PrivateKey) keyStore.getKey(userName + "pe", password));

            userKeyPair = keyPair;
        } catch (KeyStoreException
                | CertificateException
                | IOException
                | NoSuchAlgorithmException
                | UnrecoverableKeyException ex) {
            throw new CryptoException("Error loadKeyPair", ex);
        }

        return keyPair;
    }

    /**
     *
     * @return
     */
    public PublicKey getPublicKey() {
        if (userKeyPair != null) {
            return userKeyPair.getPublic();
        }
        return null;
    }

    /**
     *
     * @throws CryptoException
     */
    public void exportPublicKey()
            throws CryptoException {
        if (userKeyPair != null) {
            try {
                X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(userKeyPair.getPublic().getEncoded());
                FileOutputStream fos = new FileOutputStream("public.key");
                fos.write(x509EncodedKeySpec.getEncoded());
                fos.close();
            } catch (IOException ex) {
                throw new CryptoException("exportPublicKey error", ex);
            }
        }
    }

    /**
     *
     * @param publicName
     * @throws CryptoException
     */
    public void loadFriendPublicKey(
            String publicName)
            throws CryptoException {
        try {
            File filePublicKey = new File(publicName);
            FileInputStream fis = new FileInputStream(publicName);
            byte[] encodedPublicKey = new byte[(int) filePublicKey.length()];
            fis.read(encodedPublicKey);
            fis.close();

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
            friendPublicKey = keyFactory.generatePublic(publicKeySpec);
        } catch (NoSuchAlgorithmException
                | InvalidKeySpecException
                |IOException ex) {
            throw new CryptoException("loadFriendPublicKey error", ex);
        }
    }

    /**
     *
     * @param pub
     * @throws CryptoException
     */
    public void loadFriendPublicKey(
            PublicKey pub)
            throws CryptoException {
            friendPublicKey = pub;
    }

    /**
     *
     * @param file
     * @return
     * @throws CryptoException
     */
    public File encryptFile(
            String file)
            throws CryptoException {
        File inputFile = new File(file);
        FileInputStream inputStream;
        FileOutputStream outputStream;
        byte[] inputBytes;
        byte[] outputBytes;
        File outputFile;

        try {
            inputStream = new FileInputStream(inputFile);

            //See AES comments
            inputBytes = new byte[(int) inputFile.length()];

            //Read return ignored
            inputStream.read(inputBytes);

            outputBytes = doCrypto(Cipher.ENCRYPT_MODE, userKeyPair.getPublic(), inputBytes);

            outputFile = new File(inputFile.getName() + ".PGP");
            outputStream = new FileOutputStream(outputFile);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();
        } catch (IOException ex) {
            throw new CryptoException("Error encryptFile", ex);
        }

        return outputFile;
    }

    /**
     *
     * @param file
     * @return
     * @throws CryptoException
     */
    public File decryptFile(
            String file)
            throws CryptoException {
        File inputFile = new File(file);
        FileInputStream inputStream;
        FileOutputStream outputStream;
        byte[] inputBytes;
        byte[] outputBytes;
        File outputFile;

        try {
            inputStream = new FileInputStream(inputFile);

            inputBytes = new byte[(int) inputFile.length()];

            inputStream.read(inputBytes);

            outputBytes = doCrypto(Cipher.DECRYPT_MODE, userKeyPair.getPrivate(), inputBytes);
            outputFile = new File("PGP" + inputFile.getName().substring(0, inputFile.getName().length() - 4));

            outputStream = new FileOutputStream(outputFile);

            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();
        } catch (IOException ex) {
            throw new CryptoException("Error decryptFile", ex);
        }

        return outputFile;
    }

    /**
     *
     * @param plaintext
     * @return
     * @throws CryptoException
     */
    public String encryptString(
            String plaintext)
            throws CryptoException {
        char[] encryptedTranspherable;

        try {
            byte[] bytes = plaintext.getBytes("UTF-8");
//            byte[] encrypted = doCrypto(Cipher.ENCRYPT_MODE, userKeyPair.getPublic(), bytes);
            byte[] encrypted = doCrypto(Cipher.ENCRYPT_MODE, friendPublicKey, bytes);
            encryptedTranspherable = Hex.encodeHex(encrypted);
        } catch (UnsupportedEncodingException ex) {
            throw new CryptoException("Error encryptString", ex);
        }

        return new String(encryptedTranspherable);
    }

    /**
     *
     * @param encrypted
     * @return
     * @throws CryptoException
     */
    public String decryptString(
            String encrypted)
            throws CryptoException {
        byte[] decrypted;

        try {
            byte[] bts = Hex.decodeHex(encrypted.toCharArray());
            decrypted = doCrypto(Cipher.DECRYPT_MODE, userKeyPair.getPrivate(), bts);
            return new String(decrypted,"UTF-8");
        } catch ( DecoderException
                | UnsupportedEncodingException ex) {
            throw new CryptoException("Error decryptString", ex);
        }
    }

    /**
     *
     * @param cipherMode
     * @param key
     * @param inputBytes
     * @return
     * @throws CryptoException
     */
    private byte[] doCrypto(
            int cipherMode,
            Key key,
            byte[] inputBytes)
            throws CryptoException {
        byte[] scrambled;
        byte[] toReturn = new byte[0];
        //Size of buff depend on encrypt or decrypt
        int length = (cipherMode == Cipher.ENCRYPT_MODE) ? 100 : 128;

        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(cipherMode, key);
            byte[] buffer = new byte[length];

            for (int i=0; i < inputBytes.length; i++){
                //System.out.println("i: " + i + "\ninputBytes.length: " + inputBytes.length);
                if ((i > 0) && (i % length == 0)){
                    scrambled = cipher.doFinal(buffer);
                    toReturn = append(toReturn,scrambled);
                    int newLength = length;

                    if (i + length > inputBytes.length) {
                        newLength = inputBytes.length - i;
                    }
                    buffer = new byte[newLength];
                }
                buffer[i%length] = inputBytes[i];
            }

            scrambled = cipher.doFinal(buffer);
            toReturn = append(toReturn,scrambled);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | BadPaddingException
                | IllegalBlockSizeException ex) {
            throw new CryptoException("Error doCrypto", ex);
        }

        return toReturn;
    }

    /**
     *
     * @param prefix
     * @param suffix
     * @return
     */
    private byte[] append(
            byte[] prefix,
            byte[] suffix){
        byte[] toReturn = new byte[prefix.length + suffix.length];
        for (int i=0; i< prefix.length; i++){
            toReturn[i] = prefix[i];
        }
        for (int i=0; i< suffix.length; i++){
            toReturn[i+prefix.length] = suffix[i];
        }
        return toReturn;
    }
}