package encryptUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import java.io.UnsupportedEncodingException;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

//Android import
//import android.util.Base64;
import org.apache.commons.codec.binary.Base64;

/**
 * Created by Madeline on 02/06/2017.
 */
public class AES256 {

    /**
     * Encryption mode enumeration
     */
    private enum EncryptMode {
        ENCRYPT, DECRYPT;
    }

    // cipher to be used for encryption and decryption
    Cipher _cx;

    // encryption key and initialization vector
    byte[] _key, _iv;

    public AES256() throws NoSuchAlgorithmException, NoSuchPaddingException {
        // initialize the cipher with transformation AES/CBC/PKCS5Padding
        _cx = Cipher.getInstance("AES/CBC/PKCS5Padding");
        //256 bit key space
        _key = new byte[32];
        //128 bit IV
        _iv = new byte[16];
    }

//    /**
//     * Note: This function is no longer used.
//     * This function generates md5 hash of the input string
//     * @param inputString
//     * @return md5 hash of the input string
//     */
//    public static final String md5(final String inputString) {
//        final String MD5 = "MD5";
//        try {
//            // Create MD5 Hash
//            MessageDigest digest = java.security.MessageDigest
//                    .getInstance(MD5);
//            digest.update(inputString.getBytes());
//            byte messageDigest[] = digest.digest();
//
//            // Create Hex String
//            StringBuilder hexString = new StringBuilder();
//            for (byte aMessageDigest : messageDigest) {
//                String h = Integer.toHexString(0xFF & aMessageDigest);
//                while (h.length() < 2)
//                    h = "0" + h;
//                hexString.append(h);
//            }
//            return hexString.toString();
//
//        } catch (NoSuchAlgorithmException e) {
//            e.printStackTrace();
//        }
//        return "";
//    }

    /**
     *
     * @param _inputText
     *            Text to be encrypted or decrypted
     * @param _encryptionKey
     *            Encryption key to used for encryption / decryption
     * @param _mode
     *            specify the mode encryption / decryption
     * @param _initVector
     * 	      Initialization vector
     * @return encrypted or decrypted string based on the mode
     * @throws UnsupportedEncodingException
     * @throws InvalidKeyException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    private String encryptDecrypt(
            String _inputText,
            String _encryptionKey,
            EncryptMode _mode,
            String _initVector)
            throws UnsupportedEncodingException,
            InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException {
        // output string
        String _out = "";

        //_encryptionKey = md5(_encryptionKey);
        //System.out.println("key="+_encryptionKey);

        // length of the key	provided
        int len = _encryptionKey.getBytes("UTF-8").length;

        if (_encryptionKey.getBytes("UTF-8").length > _key.length)
            len = _key.length;

        int ivlen = _initVector.getBytes("UTF-8").length;

        if(_initVector.getBytes("UTF-8").length > _iv.length)
            ivlen = _iv.length;

        System.arraycopy(_encryptionKey.getBytes("UTF-8"), 0, _key, 0, len);
        System.arraycopy(_initVector.getBytes("UTF-8"), 0, _iv, 0, ivlen);

        //KeyGenerator _keyGen = KeyGenerator.getInstance("AES");
        //_keyGen.init(128);

        // Create a new SecretKeySpec for the specified key data and
        // algorithm name.
        SecretKeySpec keySpec = new SecretKeySpec(_key, "AES");

        // Create a new IvParameterSpec instance with the bytes from the
        // specified buffer iv used as initialization vector.
        IvParameterSpec ivSpec = new IvParameterSpec(_iv);

        // encryption
        if (_mode.equals(EncryptMode.ENCRYPT)) {
            // Potentially insecure random numbers on Android 4.3 and older.
            // Read
            // https://android-developers.blogspot.com/2013/08/some-securerandom-thoughts.html
            // for more info.

            // Initialize this cipher instance
            _cx.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);
            // Finish multi-part transformation (encryption)
            byte[] results = _cx.doFinal(_inputText.getBytes("UTF-8"));

            // ciphertext output Android
            //_out = Base64.encodeToString(results, Base64.DEFAULT);
            // ciphertext output
            _out = Base64.encodeBase64String(results);
        }

        // decryption
        if (_mode.equals(EncryptMode.DECRYPT)) {
            // Initialize this cipher instance
            _cx.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
            //byte[] decodedValue = Base64.decode(_inputText.getBytes(),Base64.DEFAULT);
            byte[] decodedValue = Base64.decodeBase64(_inputText.getBytes());

            // Finish multi-part transformation(decryption)
            byte[] decryptedVal = _cx.doFinal(decodedValue);
            // decrypttext output
            _out = new String(decryptedVal);
        }
        // return encrypted/decrypted string
        return _out;
    }

    /***
     * This function computes the SHA256 hash of input string
     * @param text input text whose SHA256 hash has to be computed
     * @param length length of the text to be returned
     * @return returns SHA256 hash of input text
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public static String SHA256 (
            String text,
            int length)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String resultStr;
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        md.update(text.getBytes("UTF-8"));
        byte[] digest = md.digest();

        StringBuffer result = new StringBuffer();
        for (byte b : digest) {
            //convert to hex
            result.append(String.format("%02x", b));
        }

        if(length > result.toString().length())
        {
            resultStr = result.toString();
        }
        else
        {
            resultStr = result.toString().substring(0, length);
        }

        return resultStr;

    }

    /***
     * This function encrypts the plain text to cipher text using the key
     * provided. You'll have to use the same key for decryption
     *
     * @param _plainText
     *            Plain text to be encrypted
     * @param _key
     *            Encryption Key. You'll have to use the same key for decryption
     * @param _iv
     * 	    initialization Vector
     * @return returns encrypted (cipher) text
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */

    public String encrypt(
            String _plainText,
            String _key,
            String _iv)
            throws InvalidKeyException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        return encryptDecrypt(_plainText, _key, EncryptMode.ENCRYPT, _iv);
    }

    /***
     * This funtion decrypts the encrypted text to plain text using the key
     * provided. You'll have to use the same key which you used during
     * encryprtion
     *
     * @param _encryptedText
     *            Encrypted/Cipher text to be decrypted
     * @param _key
     *            Encryption key which you used during encryption
     * @param _iv
     * 	    initialization Vector
     * @return encrypted value
     * @throws InvalidKeyException
     * @throws UnsupportedEncodingException
     * @throws InvalidAlgorithmParameterException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String decrypt(
            String _encryptedText,
            String _key,
            String _iv)
            throws InvalidKeyException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException, IllegalBlockSizeException,
            BadPaddingException {
        return encryptDecrypt(_encryptedText, _key, EncryptMode.DECRYPT, _iv);
    }

    /**
     * this function generates random string for given length
     * @param length
     * 				Desired length
     * * @return
     */
    public static String generateRandomIV(
            int length)
    {
        SecureRandom ranGen = new SecureRandom();
        byte[] aesKey = new byte[16];
        ranGen.nextBytes(aesKey);
        StringBuffer result = new StringBuffer();
        for (byte b : aesKey) {
            //convert to hex
            result.append(String.format("%02x", b));
        }
        if(length> result.toString().length())
        {
            return result.toString();
        }
        else
        {
            return result.toString().substring(0, length);
        }
    }
}
