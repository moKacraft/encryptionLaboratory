/**
 * Created by Madeline on 03/03/2017.
 */

package encryptUtils;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
//import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
//import org.bouncycastle.openpgp.PGPObjectFactory;

import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;

import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;

import org.bouncycastle.util.io.Streams;

import java.io.*;

import java.security.*;

import java.util.Date;
import java.util.Iterator;

public class PGPBouncy {

    public PGPBouncy() {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     *
     * @param identity
     * @param passPhrase
     * @param armor
     * @throws IOException
     * @throws InvalidKeyException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws PGPException
     * @throws NoSuchAlgorithmException
     */
    public void exportKeyPair(
            String          identity,
            char[]          passPhrase,
            boolean         armor)
            throws IOException, InvalidKeyException, NoSuchProviderException, SignatureException, PGPException, NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");

        kpg.initialize(1024);

        KeyPair pair = kpg.generateKeyPair();

        OutputStream secretOut = new FileOutputStream("secret.asc");
        OutputStream publicOut = new FileOutputStream("pub.asc");

        if (armor) {
            secretOut = new ArmoredOutputStream(secretOut);
        }

        PGPDigestCalculator sha1Calc = new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1);
        PGPKeyPair keyPair = new JcaPGPKeyPair(PGPPublicKey.RSA_GENERAL, pair, new Date());
        PGPSecretKey secretKey = new PGPSecretKey(PGPSignature.DEFAULT_CERTIFICATION,
                keyPair,
                identity,
                sha1Calc,
                null,
                null,
                new JcaPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1),
                new JcePBESecretKeyEncryptorBuilder(PGPEncryptedData.CAST5, sha1Calc).setProvider("BC").build(passPhrase));
        secretKey.encode(secretOut);
        secretOut.close();

        if (armor) {
            publicOut = new ArmoredOutputStream(publicOut);
        }

        PGPPublicKey key = secretKey.getPublicKey();
        key.encode(publicOut);
        publicOut.close();
    }

    /**
     *
     * @param fileName
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private PGPPublicKey readPublicKey(
            String fileName)
            throws IOException, PGPException {
        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
        PGPPublicKey pubKey = readPublicKey(keyIn);
        keyIn.close();

        return pubKey;
    }

    /**
     *
     * @param input
     * @return
     * @throws IOException
     * @throws PGPException
     */
    private PGPPublicKey readPublicKey(
            InputStream input)
            throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());

        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();

            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext()) {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();

                if (key.isEncryptionKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

//    static PGPSecretKey readSecretKey(
//            String fileName)
//            throws IOException, PGPException {
//        InputStream keyIn = new BufferedInputStream(new FileInputStream(fileName));
//        PGPSecretKey secKey = readSecretKey(keyIn);
//        keyIn.close();
//        return secKey;
//    }

//    static private PGPSecretKey readSecretKey(
//            InputStream input)
//            throws IOException, PGPException {
//        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
//                PGPUtil.getDecoderStream(input), new JcaKeyFingerprintCalculator());
//
//
//        Iterator keyRingIter = pgpSec.getKeyRings();
//        while (keyRingIter.hasNext())
//        {
//            PGPSecretKeyRing keyRing = (PGPSecretKeyRing)keyRingIter.next();
//
//            Iterator keyIter = keyRing.getSecretKeys();
//            while (keyIter.hasNext())
//            {
//                PGPSecretKey key = (PGPSecretKey)keyIter.next();
//
//                if (key.isSigningKey())
//                {
//                    return key;
//                }
//            }
//        }
//
//        throw new IllegalArgumentException("Can't find signing key in key ring.");
//    }

    /**
     *
     * @param pgpSec
     * @param keyID
     * @param pass
     * @return
     * @throws PGPException
     * @throws NoSuchProviderException
     */
    static private PGPPrivateKey findSecretKey(
            PGPSecretKeyRingCollection pgpSec,
            long keyID,
            char[] pass)
            throws PGPException, NoSuchProviderException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        return pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider("BC").build(pass));
    }

    /**
     *
     * @param inputFileName
     * @param keyFileName
     * @param password
     * @param defaultFileName
     * @throws IOException
     * @throws NoSuchProviderException
     */
    public void decryptFile(
            String inputFileName,
            String keyFileName,
            char[] password,
            String defaultFileName)
            throws IOException, NoSuchProviderException {
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
        decryptFile(in, keyIn, password, defaultFileName);
        keyIn.close();
        in.close();
    }

    /**
     *
     * @param in
     * @param keyIn
     * @param password
     * @param defaultFileName
     * @throws IOException
     * @throws NoSuchProviderException
     */
    private void decryptFile(
            InputStream in,
            InputStream keyIn,
            char[]      password,
            String      defaultFileName)
            throws IOException, NoSuchProviderException {
        in = PGPUtil.getDecoderStream(in);

        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;

            Object o = pgpF.nextObject();

            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList)o;
            }
            else {
                enc = (PGPEncryptedDataList)pgpF.nextObject();
            }

            Iterator it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData)it.next();

                sKey = findSecretKey(pgpSec, pbe.getKeyID(), password);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));

            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);

            PGPCompressedData cData = (PGPCompressedData)plainFact.nextObject();

            InputStream compressedStream = new BufferedInputStream(cData.getDataStream());
            JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(compressedStream);

            Object message = pgpFact.nextObject();

            if (message instanceof PGPLiteralData) {
                PGPLiteralData ld = (PGPLiteralData)message;

                String outFileName = defaultFileName;

                InputStream unc = ld.getInputStream();
                OutputStream fOut =  new BufferedOutputStream(new FileOutputStream(outFileName));

                Streams.pipeAll(unc, fOut);

                fOut.close();
            }
            else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            }
            else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }

            if (pbe.isIntegrityProtected()) {
                if (!pbe.verify()) {
                    System.err.println("message failed integrity check");
                }
                else {
                    System.err.println("message integrity check passed");
                }
            }
            else {
                System.err.println("no message integrity check");
            }
        }
        catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    /**
     *
     * @param outputFileName
     * @param inputFileName
     * @param encKeyFileName
     * @param armor
     * @param withIntegrityCheck
     * @throws IOException
     * @throws NoSuchProviderException
     * @throws PGPException
     */
    public void encryptFile(
            String          outputFileName,
            String          inputFileName,
            String          encKeyFileName,
            boolean         armor,
            boolean         withIntegrityCheck)
            throws IOException, NoSuchProviderException, PGPException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        PGPPublicKey encKey = readPublicKey(encKeyFileName);
        encryptFile(out, inputFileName, encKey, armor, withIntegrityCheck);
        out.close();
    }

    /**
     *
     * @param out
     * @param fileName
     * @param encKey
     * @param armor
     * @param withIntegrityCheck
     * @throws IOException
     * @throws NoSuchProviderException
     */
    private void encryptFile(
            OutputStream    out,
            String          fileName,
            PGPPublicKey    encKey,
            boolean         armor,
            boolean         withIntegrityCheck)
            throws IOException, NoSuchProviderException {
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        try {
            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));

            cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

            OutputStream cOut = cPk.open(out, new byte[1 << 16]);

            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

            PGPUtil.writeFileToLiteralData(comData.open(cOut), PGPLiteralData.BINARY, new File(fileName), new byte[1 << 16]);

            comData.close();

            cOut.close();

            if (armor) {
                out.close();
            }
        }
        catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

//    public final byte[] encrypt(
//            byte[] input) {
//        try {
//
//            PGPPublicKey publicKey = readPublicKey("pub.asc");
//
//            ByteArrayOutputStream out = new ByteArrayOutputStream();
//
//            JcePGPDataEncryptorBuilder PgpDataEncryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC");
//            PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(PgpDataEncryptorBuilder);
//            encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setProvider("BC"));
//            OutputStream dataGeneratorOut = encryptedDataGenerator.open(out, new byte[1 << 16]);
//            PGPCompressedDataGenerator  compressDataGeneratorOut = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
//
//            writeBytesToLiteralData(compressDataGeneratorOut.open(dataGeneratorOut), PGPLiteralData.BINARY, "data-input.bin", input);
//
//            compressDataGeneratorOut.close();
//            dataGeneratorOut.close();
//            out.close();
//
//            return out.toByteArray();
//
//        } catch (Exception e) {
//            throw new RuntimeException("error.pgp.cipher", e);
//        }
//    }
//
//    private static void writeBytesToLiteralData(OutputStream out, char fileType, String name, byte[] bytes) throws IOException {
//        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
//        OutputStream pOut = lData.open(out, fileType, name,bytes.length, new Date());
//        pOut.write(bytes);
//    }
//
//
//    public final byte[] decrypt(
//            byte[] encrypted,
//            char[] password) {
//        try {
//            InputStream keyIn = new ByteArrayInputStream(keyRing);
//            InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(encrypted));
//
//            PGPObjectFactory pgpObjFactory = new PGPObjectFactory(in, getKeyFingerPrintCalculator());
//            PGPEncryptedDataList pgpEncryptedDataList = null;
//
//            Object o = pgpObjFactory.nextObject();
//            if (o instanceof PGPEncryptedDataList) {
//                pgpEncryptedDataList = (PGPEncryptedDataList) o;
//            } else {
//                pgpEncryptedDataList = (PGPEncryptedDataList) pgpObjFactory.nextObject();
//            }
//
//            PGPPrivateKey secretKey = null;
//            PGPPublicKeyEncryptedData publicKeyEncryptedData = null;
//            PGPSecretKeyRingCollection pgpSecretKeyRingCollection = new PGPSecretKeyRingCollection(
//                    PGPUtil.getDecoderStream(keyIn), getKeyFingerPrintCalculator());
//
//            Iterator<?> it = pgpEncryptedDataList.getEncryptedDataObjects();
//
//            while (it.hasNext() && secretKey == null) {
//                publicKeyEncryptedData = (PGPPublicKeyEncryptedData) it.next();
//                PGPSecretKey pgpSecKey = pgpSecretKeyRingCollection.getSecretKey(publicKeyEncryptedData.getKeyID());
//
//                if (pgpSecKey != null) {
//                    Provider provider = Security.getProvider("BC");
//                    secretKey = pgpSecKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder(
//                            new JcaPGPDigestCalculatorProviderBuilder().setProvider(provider).build())
//                            .setProvider(provider).build(password));
//                }
//            }
//
//            if (secretKey == null) {
//                throw new IllegalArgumentException("secret key for message not found.");
//            }
//
//            if (publicKeyEncryptedData == null) {
//                throw new NullPointerException("cannot continue with null public key encryption data.");
//            }
//
//            InputStream clear = publicKeyEncryptedData
//                    .getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(secretKey));
//            PGPObjectFactory plainFact = new PGPObjectFactory(clear, getKeyFingerPrintCalculator());
//            PGPCompressedData compressedData = (PGPCompressedData) plainFact.nextObject();
//            InputStream compressedStream = new BufferedInputStream(compressedData.getDataStream());
//            PGPObjectFactory pgpFact = new PGPObjectFactory(compressedStream, getKeyFingerPrintCalculator());
//            Object message = pgpFact.nextObject();
//
//            ByteArrayOutputStream bos = new ByteArrayOutputStream();
//
//            if (message instanceof PGPLiteralData) {
//                PGPLiteralData literalData = (PGPLiteralData) message;
//                InputStream is = literalData.getInputStream();
//
//                int nRead;
//                byte[] data = new byte[16384];
//
//                while ((nRead = is.read(data, 0, data.length)) != -1) {
//                    bos.write(data, 0, nRead);
//                }
//
//                bos.flush();
//
//            } else if (message instanceof PGPOnePassSignatureList) {
//                throw new PGPException("encrypted message contains a signed message - not literal data.");
//
//            } else {
//                throw new PGPException("message is not a simple encrypted file - type unknown.");
//
//            }
//
//            bos.close();
//
//            if (publicKeyEncryptedData.isIntegrityProtected()) {
//                if (!publicKeyEncryptedData.verify()) throw new PGPException("message failed integrity check");
//
//            }
//
//            keyIn.close();
//            in.close();
//
//
//            return bos.toByteArray();
//
//        } catch (Exception e) {
//            throw new RuntimeException("error.pgp.cipher", e);
//        }
//
//
//    }


//    public static byte[] encryptByte(
//            String          inputFileName,
//            String          encKeyFileName,
//            boolean         armor,
//            boolean         withIntegrityCheck)
//            throws IOException, NoSuchProviderException, PGPException {
//        PGPPublicKey encKey = readPublicKey(encKeyFileName);
//        return (encryptFile(inputFileName, encKey, armor, withIntegrityCheck));
//    }
//
//    private static byte[] encryptByte(
//            String          fileName,
//            PGPPublicKey    encKey,
//            boolean         armor,
//            boolean         withIntegrityCheck)
//            throws IOException, NoSuchProviderException {
//
//        try {
//            PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck).setSecureRandom(new SecureRandom()).setProvider("BC"));
//
//            cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
//
//            OutputStream cOut = cPk.open(out, new byte[1 << 16]);
//
//            PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
//
//            PGPUtil.writeFileToLiteralData(comData.open(cOut), PGPLiteralData.BINARY, new File(fileName), new byte[1 << 16]);
//
//            comData.close();
//
//            cOut.close();
//
//
//            return ();
//        }
//        catch (PGPException e) {
//            System.err.println(e);
//            if (e.getUnderlyingException() != null) {
//                e.getUnderlyingException().printStackTrace();
//            }
//        }
//    }


//    private static byte[] compress(
//            byte[] clearData,
//            String fileName,
//            int algorithm)
//            throws IOException {
//        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(algorithm);
//        OutputStream cos = comData.open(bOut); // open it with the final destination
//
//        PGPLiteralDataGenerator lData = new PGPLiteralDataGenerator();
//
//        OutputStream  pOut = lData.open(cos, // the compressed output stream
//                PGPLiteralData.BINARY,
//                fileName,  // "filename" to store
//                clearData.length, // length of clear data
//                new Date());
//
//        pOut.write(clearData);
//        pOut.close();
//
//        comData.close();
//
//        return bOut.toByteArray();
//    }
//
//    public static byte[] encryptByteArray(
//            byte[]  clearData,
//            String key,
//            String  fileName,
//            boolean armor)
//            throws IOException, PGPException, NoSuchProviderException
//    {
//        PGPPublicKey encKey = readPublicKey(key);
//
//        if (fileName == null) {
//            fileName= PGPLiteralData.CONSOLE;
//        }
//
//        byte[] compressedData = compress(clearData, fileName, CompressionAlgorithmTags.ZIP);
//
//        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
//
//        OutputStream out = bOut;
//        if (armor) {
//            out = new ArmoredOutputStream(out);
//        }
//
//        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider("BC"));
//
//        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
////        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(algorithm).setSecureRandom(new SecureRandom()).setProvider("BC"));
////        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator(passPhrase).setProvider("BC"));
//
//        OutputStream encOut = encGen.open(out, compressedData.length);
//
//        encOut.write(compressedData);
//        encOut.close();
//
//        if (armor) {
//            out.close();
//        }
//
//        return bOut.toByteArray();
//    }
//
//    public static byte[] decryptByteArray(
//            byte[] encrypted,
//            String keyFileName,
//            char[] password)
//            throws IOException, PGPException, NoSuchProviderException
//    {
//        InputStream in = new ByteArrayInputStream(encrypted);
//
//        in = PGPUtil.getDecoderStream(in);
//
//        JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(in);
//        PGPEncryptedDataList enc;
//        Object o = pgpF.nextObject();
//
//        if (o instanceof PGPEncryptedDataList) {
//            enc = (PGPEncryptedDataList)o;
//        }
//        else {
//            enc = (PGPEncryptedDataList)pgpF.nextObject();
//        }
//
//        InputStream keyIn = new BufferedInputStream(new FileInputStream(keyFileName));
//        Iterator it = enc.getEncryptedDataObjects();
//        PGPPrivateKey sKey = null;
//        PGPPublicKeyEncryptedData ppbe = null;
//        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
//                PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());
//
//        while (sKey == null && it.hasNext()) {
//            ppbe = (PGPPublicKeyEncryptedData)it.next();
//
//            sKey = findSecretKey(pgpSec, ppbe.getKeyID(), password);
//        }
//
//        if (sKey == null) {
//            throw new IllegalArgumentException("secret key for message not found.");
//        }
//
//        InputStream clear = ppbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
//
////        PGPPBEEncryptedData pbe = (PGPPBEEncryptedData)enc.get(0);
////
////        InputStream clear = pbe.getDataStream(new JcePBEDataDecryptorFactoryBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC").build(passPhrase));
//
//        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(clear);
//
//        PGPCompressedData cData = (PGPCompressedData)pgpFact.nextObject();
//
//        pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
//
//        PGPLiteralData ld = (PGPLiteralData)pgpFact.nextObject();
//
//        return Streams.readAll(ld.getInputStream());
//    }
}
