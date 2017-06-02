/**
 * Created by Madeline on 08/01/2017.
 */

package encryptUtils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.security.cert.CertificateException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;

import java.util.logging.FileHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class AES {

    private SecretKey userKey = null;

    private final int KEY_SIZE = 128;
    private final int BUFFER_SIZE = 30000000;

    private final int LOG_SIZE = 1000000;
    private final int LOG_ROTATION_COUNT = 1;

    private Logger log = Logger.getLogger("Logging info");

    private final String ENCRYPTION_INSTANCE = "AES";
//    private final String ENCRYPTION_INSTANCE = "AES/CBC/NoPadding";
   // private final String ENCRYPTION_INSTANCE = "AES/CBC/PKCS5Padding";
    private final String KEYSTORE_INSTANCE = "JCEKS";

    /**
     *
     * @throws IOException
     */
    public AES()
            throws IOException {
        Handler handler = new FileHandler("encrypt.log", LOG_SIZE, LOG_ROTATION_COUNT);
        log.addHandler(handler);
    }

    /**
     *
     * @param password
     * @param userName
     * @throws NoSuchAlgorithmException
     */
    public void generateKey(
            char[] password,
            String userName)
            throws CryptoException {
        KeyGenerator KeyGen;
        SecretKey SecKey;

        try {
            log.info("KeyGenerator.getInstance");
            KeyGen = KeyGenerator.getInstance("AES");
        } catch (NoSuchAlgorithmException ex) {
            throw new CryptoException("Error generateKey", ex);
        }
        log.info("KeyGen.init");
        KeyGen.init(KEY_SIZE);
        log.info("KeyGen.generateKey");
        SecKey = KeyGen.generateKey();
        log.info("saveKey");
        saveKey(SecKey, password, userName);
    }

    /**
     *
     * @param key
     * @param password
     * @param userName
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    private void saveKey(
            SecretKey key,
            char[] password,
            String userName)
            throws CryptoException {
        KeyStore keyStore;

        try {
            log.info("KeyStore.getInstance");
            keyStore = KeyStore.getInstance("JCEKS");
            log.info("keyStore.load");
            keyStore.load(null, null);
            log.info("keyStore.setEntry");
            keyStore.setKeyEntry(userName, key, password, null);
            log.info("keyStore.store");
            keyStore.store(new FileOutputStream(userName + ".jceks"), password);

            userKey = key;
        } catch (KeyStoreException
                | IOException
                | NoSuchAlgorithmException
                | CertificateException ex) {
            throw new CryptoException("Error saveKey", ex);
        }
    }

    /**
     *
     * @param password
     * @param userName
     * @throws CryptoException
     */
    public void loadKey(
            char[] password,
            String userName)
            throws CryptoException {
        KeyStore keyStore;
        SecretKey key;

        try {
            log.info("KeyStore.getInstance");
            keyStore = KeyStore.getInstance("JCEKS");
            log.info("keyStore.load");
            keyStore.load(new FileInputStream(userName + ".jceks"), password);
            log.info("keyStore.getKey");
            key = (SecretKey) keyStore.getKey(userName, password);

            userKey = key;
        } catch (KeyStoreException
                | CertificateException
                | IOException
                | NoSuchAlgorithmException
                | UnrecoverableKeyException ex) {
            throw new CryptoException("Error loadKey", ex);
        }
    }

    /**
     *
     * @return
     */
    public SecretKey getUserKey() {
        return userKey;
    }

    /**
     *
     * @param toEncrypt
     * @return
     * @throws CryptoException
     */
    public byte[] encryptString(
            String toEncrypt)
            throws CryptoException {
        byte[] toEncryptBytes;
        byte[] outputBytes;

        try {
            log.info("toEncrypt.getBytes");
            toEncryptBytes = toEncrypt.getBytes("UTF8");
            log.info("encryptString.doCrypto");
            outputBytes = doCrypto(Cipher.ENCRYPT_MODE, toEncryptBytes);
        } catch (UnsupportedEncodingException ex) {
            throw new CryptoException("Error encryptString", ex);
        }

        return outputBytes;
    }

    /**
     *
     * @param toDecryptBytes
     * @return
     * @throws CryptoException
     */
    public String decryptString(
            byte[] toDecryptBytes)
            throws CryptoException {
        byte[] outputBytes;
        String cipherText;

        log.info("decryptString.doCrypto");
        outputBytes = doCrypto(Cipher.DECRYPT_MODE, toDecryptBytes);
        cipherText = new String(outputBytes);

        return cipherText;
    }

    /**
     *
     * @param inputFile
     * @return
     * @throws CryptoException
     */
    public File encryptFile(
            File inputFile)
            throws CryptoException {
        FileInputStream inputStream;
        FileOutputStream outputStream;
        File outputFile;
        byte[] inputBytes;
        byte[] outputBytes;

        int fileLength = (int) inputFile.length();
        int length = (inputFile.length() > BUFFER_SIZE) ? BUFFER_SIZE : fileLength;
        int lastBuffer = fileLength % BUFFER_SIZE;

        System.out.println("length: " + length);
        System.out.println("lastBuffer: " + lastBuffer);
        try {
            inputStream = new FileInputStream(inputFile);

            outputFile = new File(inputFile.getName() + ".AES");

            if (outputFile.exists() && !outputFile.isDirectory()) {
                System.out.println("File already exists");
                outputFile.delete();
            }

            //true for append
            outputStream = new FileOutputStream(outputFile, true);

            System.out.println("inputFileLength: " + fileLength);

            int i = 0;
            while (i != fileLength) {
                inputBytes = new byte[length];
                System.out.println("i: " + i);
                System.out.println("length: " + length);
                //inputStream.read(inputBytes, i, length);
                //read only first bytes maybe need to skip data from stream
                inputStream.read(inputBytes);

                outputBytes = doCrypto(Cipher.ENCRYPT_MODE, inputBytes);

                outputStream.write(outputBytes);

                if (i + lastBuffer == fileLength) {
                    length = lastBuffer;
                    i += length;
                } else {
                    i += length;
                }
            }

            inputStream.close();
            outputStream.close();
        } catch (IOException ex) {
            throw new CryptoException("Error encryptFile", ex);
        }
        return outputFile;
    }

    /**
     *
     * @param inputFile
     * @return
     * @throws CryptoException
     */
    public File decryptFile(
            File inputFile)
            throws CryptoException {
        FileInputStream inputStream;
        FileOutputStream outputStream;
        byte[] inputBytes;
        byte[] outputBytes;
        File outputFile;

        int fileLength = (int) inputFile.length();
        int length = (inputFile.length() > BUFFER_SIZE) ? BUFFER_SIZE : fileLength;
        int lastBuffer = fileLength % BUFFER_SIZE;

        try {
            log.info("inputStream = new FileInputStream(inputFile)");
            inputStream = new FileInputStream(inputFile);
            log.info("outputFile = new File");
            outputFile = new File("AES" + inputFile.getName().substring(0, inputFile.getName().length() - 4));

            if (outputFile.exists() && !outputFile.isDirectory()) {
                log.info("outputFile already exists");
                outputFile.delete();
            }

            log.info("outputStream = new FileOutputStream(outputFile)");
            outputStream = new FileOutputStream(outputFile, true);

            int i = 0;
            while (i != fileLength) {

                log.info("inputBytes = new byte[length];");
                inputBytes = new byte[length];

                log.info("inputStream.read(inputBytes);");
                inputStream.read(inputBytes);
                log.info("outputBytes = doCrypto");
                outputBytes = doCrypto(Cipher.DECRYPT_MODE, inputBytes);

                log.info("outputStream.write(outputBytes)");
                outputStream.write(outputBytes);

                if (i + lastBuffer == fileLength) {
                    length = lastBuffer;
                    i += length;
                } else {
                    i += length;
                }
            }

            log.info("inputStream.close()");
            inputStream.close();
            log.info("outputStream.close()");
            outputStream.close();
        } catch (IOException ex) {
            throw new CryptoException("Error decryptFile", ex);
        }
        return outputFile;
    }

    /**
     *
     * @param cipherMode
     * @param inputBytes
     * @return
     * @throws CryptoException
     */
    private byte[] doCrypto(
            int cipherMode,
            byte[] inputBytes)
            throws CryptoException {
        Cipher cipher;
        byte[] outputBytes;

        try {
            log.info("Cipher.getInstance");
//            cipher = Cipher.getInstance("AES");
            cipher = Cipher.getInstance(ENCRYPTION_INSTANCE);
            log.info("cipher.init");
            cipher.init(cipherMode, userKey);
            log.info("cipher.doFinal");
            outputBytes = cipher.doFinal(inputBytes);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException ex) {
            throw new CryptoException("Error doCrypto", ex);
        }
        return outputBytes;
    }


}
