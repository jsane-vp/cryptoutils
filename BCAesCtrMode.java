import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Base64;
import java.util.Arrays;
import java.math.BigInteger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.nio.*;
import java.nio.charset.StandardCharsets;

// Requires Bouncy Castle cryptographic provider jar installed 
// and supplied when compiling it.
// Tested with bcprov-ext-jdk15on-167.jar

// Wrapper class around Bouncy Castle's AES counter mode implementation
// It keeps track of the (IV+)counter and adds a HMAC to the cipher text
// to discourage casual chosen cipher text attacks. 
public class BCAesCtrMode
{
    int IV_COUNTER_SIZE = 16;
    int IV_SIZE = 12;    // iv portion
    int BLOCK_SIZE = 16;
    int MINI_HASH = 4;
    int SIZE_OF_INT = 4; 

    // TODO:: The key should be obscured if held in memory. 
    // Ideally it should disposed off quickly 
    private byte[] _key;

    // must be unique for every key
    private byte[] _ba_ivCtrEncrypt;   // used during encryption
    private int _ctr; // internal counter portion
    private byte[] _ba_ivCtrDecrypt; // used during decryption 

    private BigInteger _bi_ivCtrEncrypt, _bi_ivCtrDecrypt;

    private Cipher _aesEncObj, _aesDecObj;
    private SecretKey sKey;
    private Mac sha256Hmac;

    public BCAesCtrMode(byte[] key, byte[] iv)
    {
        // TODO:: Ensure the incoming key is 256 bits and IV is of 96 bit size
        _key = Arrays.copyOf(key, key.length);

        // Big integer treats the last byte as LSB and will 
        // increment from there. We want the counter portion
        // to increment so counter is kept in the last four bytes.
        _ba_ivCtrEncrypt = new byte[iv.length + SIZE_OF_INT];
        _ba_ivCtrDecrypt = new byte[iv.length + SIZE_OF_INT];
        _ctr = 0;
        
        _ba_ivCtrEncrypt = Arrays.copyOf(iv, iv.length + SIZE_OF_INT);      
        _ba_ivCtrDecrypt = Arrays.copyOf(iv, iv.length + SIZE_OF_INT);

        init();
    }

    private void init()
    {
        try {           
            sKey = new SecretKeySpec(_key, 0, _key.length, "AES");

            // In case the default provider do not support CTR mode
            Security.addProvider(new BouncyCastleProvider());
            _aesEncObj = Cipher.getInstance("AES/CTR/NoPadding");
            _aesDecObj = Cipher.getInstance("AES/CTR/NoPadding");

            SecretKeySpec hmacKeySpec = new SecretKeySpec(_key, "HmacSHA256");
            sha256Hmac = Mac.getInstance("HmacSHA256");
            sha256Hmac.init(hmacKeySpec);
      
            _bi_ivCtrEncrypt = new BigInteger(_ba_ivCtrEncrypt);
        } catch (Exception e) {
            //TODO: handle exception
            System.out.println("Exception - init method");
        }
    }    

    private byte[] encodeCounter(int test)
    {
        // NOTE: Counter value cannot be more than 15 bits long (2^15)
        // which is about 32,767. This fits in two bytes. 

        // Encoding format:
        // - MSB bit of first byte denotes if there is an additional byte
        //   after this byte holding the counter value. 
        //   0 - No additional bytes. Counter value is rest of 7 LSB bits
        //   1 - One additional byte following this. 
        //       Counter value: ((byte0 & 0x7F) << 8) + byte1

        // The value across the bytes is represented in big endian format.
        byte[] ctrBytes;

        // TODO:: FOR TESTING PURPOSE ONLY..REMOVE
        _ctr = test;

        if (_ctr <= 0x7F)
        {
            ctrBytes = new byte[1];
            ctrBytes[0] = (byte)_ctr;
        }
        else
        {
            ctrBytes = new byte[2];
            ctrBytes[1] = (byte)(_ctr & 0xFF);
            ctrBytes[0] = (byte)((_ctr >> 8) & (byte)0x7F);
            ctrBytes[0] |= (byte)0x80;
        }

        return ctrBytes;        
    }

    private int decodeCounter(byte[] encodedCtr)
    {
        int counterValue;

        // TODO: throw an exception if the byte array is longer than 2
        if (encodedCtr.length == 1)
            counterValue = (int)(encodedCtr[0] & (byte)0x7F);
        else
        {
            // java does not support unsigned bytes $#%^&
            encodedCtr[0] &= (byte)0x7F; 
            int msb = encodedCtr[1] >> 7;
            counterValue = (int)(encodedCtr[0] << 8);
            encodedCtr[1] &= (byte)0x7F;
            counterValue |= encodedCtr[1];
            if (msb != 0)
                counterValue |= 0x80;
        }
        return counterValue;
    }

    private byte[] encrypt(byte[] inputBytes)
    {
        try {           
            IvParameterSpec ivSpec = new IvParameterSpec(_bi_ivCtrEncrypt.toByteArray());
            _aesEncObj.init(Cipher.ENCRYPT_MODE, sKey, ivSpec);

            // Record the current counter value (throw error if large than 7FFF)
            byte[] encodedCtr = encodeCounter(_ctr);

            byte[] cipherText = _aesEncObj.doFinal(inputBytes);
            byte[] finalCipherTxt = new byte[encodedCtr.length + cipherText.length];

            // We call the underlying AES encrypt
            // encode the counter to the beginning of the out buffer.
            // TODO:: Need to find a more efficient method so we don't copy again
            System.arraycopy(encodedCtr, 0, finalCipherTxt, 0, encodedCtr.length);
            System.arraycopy(cipherText, 0, finalCipherTxt, encodedCtr.length, cipherText.length);

            // The counter and BigInteger (IV + Counter) must be kept upto date.
            // Increment the counter to (inputBytes.length / 16) + 1
            int increment = ((inputBytes.length / 16) + 1);
            _ctr += increment;
            _bi_ivCtrEncrypt  = _bi_ivCtrEncrypt.add(BigInteger.valueOf(increment));

            return finalCipherTxt;
        } catch (Exception e) {
            //TODO: handle exception
        }
        return null;
    }

    private byte[] decrypt(byte[] cipherText)
    {
        try {
            byte[] ctrBytes = new byte[ (int)(cipherText[0] >> 7) + 1];
            int counterValue;
            
            System.arraycopy(cipherText, 0, ctrBytes, 0, ctrBytes.length);
            counterValue = decodeCounter(ctrBytes);

            // Combine counter and IV
            _bi_ivCtrDecrypt = new BigInteger(_ba_ivCtrDecrypt);
            _bi_ivCtrDecrypt = _bi_ivCtrDecrypt.add(BigInteger.valueOf(counterValue));

            IvParameterSpec ivSpec = new IvParameterSpec(_bi_ivCtrDecrypt.toByteArray());
            _aesDecObj.init(Cipher.DECRYPT_MODE, sKey, ivSpec);

            byte[] justCipherText = Arrays.copyOfRange(cipherText, ctrBytes.length, 
                               cipherText.length);

            return _aesDecObj.doFinal(justCipherText);

        } catch (Exception e) {
            //TODO: handle exception
            System.out.format("Exception during decrypt - %s", e.getMessage());
        }
        return null;
    }

    // HMAC of given byte stream + IV
    // Does hmac twice and returns a minified hash of 4 bytes
    private byte[] computeHmac(byte[] cipherText)
    {
        try {
            byte[] hashInput = new byte[cipherText.length + IV_SIZE];
            System.arraycopy(cipherText, 0, hashInput, 0, cipherText.length);
            System.arraycopy(_ba_ivCtrEncrypt, 0, hashInput, cipherText.length, IV_SIZE);

            byte[] interimHash = sha256Hmac.doFinal(hashInput);
            interimHash = sha256Hmac.doFinal(interimHash);

            byte[] finalHash = new byte[MINI_HASH];
            System.arraycopy(interimHash, 0, finalHash, 0, MINI_HASH);

            return finalHash;
        } catch (Exception e) {
            //TODO: handle exception
            System.out.println("Exception caught in computeHmac");
        }
        return new byte[1];
    }

    public byte[] Encrypt(byte[] clearText)
    {
        byte[] cipherText = encrypt(clearText);
        byte[] hmac = computeHmac(cipherText);
        byte[] authenticatedCipherTxt = new byte[cipherText.length + hmac.length];

        System.arraycopy(cipherText, 0, authenticatedCipherTxt, 0, cipherText.length);
        System.arraycopy(hmac, 0, authenticatedCipherTxt, cipherText.length, hmac.length);

        return authenticatedCipherTxt;
    }

    public byte[] Decrypt(byte[] cipherText) throws Exception
    {
        byte[] ctrPlusCipherText =  Arrays.copyOfRange(cipherText, 0,
                                        cipherText.length - MINI_HASH); 
        // Verify HMAC.
        // Incoming format: <counter><pure-cipher-text><minified-hmac>
        byte[] computedHmac = computeHmac(ctrPlusCipherText);
        byte[] givenHash = Arrays.copyOfRange(cipherText, 
                                    cipherText.length - MINI_HASH, cipherText.length);
        
        if (!Arrays.equals(computedHmac, givenHash))
            throw new Exception("Tampered ciphertext detected or wrong key or IV value");

        return decrypt(ctrPlusCipherText);
    }

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for(byte b: a)
           sb.append(String.format("%02x", b));
        return sb.toString();
     }

     public static void main(String[] args)
     {
        // TODO:: Get cryptographic random key and iv bytes
        // Testing purposes only
        byte[] key = new byte[] { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
        byte[] iv = new byte[] { 20,21,22,23,24,25,26,27,28,29,30,31};

        BCAesCtrMode acm = new BCAesCtrMode(key, iv);

        // Test code to exercise the implementation
        String secret = "Test!";
        byte[] clear; // = secret.getBytes(StandardCharsets.US_ASCII);
        clear = new byte[80];
        byte[] decryptedBytes;
        byte[] cipherText;
        try {            
            for (int i=0; i < 10; i++)
            {
                cipherText = acm.Encrypt(clear);
                System.out.println(byteArrayToHex(cipherText));
                decryptedBytes = acm.Decrypt(cipherText);

                // Uncomment this if you are decrypting a printable string.
                //System.out.println(new String(decryptedBytes, StandardCharsets.US_ASCII));
                System.out.println(byteArrayToHex(decryptedBytes));
            }
        } catch (Exception e) {
            //TODO: handle exception
            System.out.println("Exception caught - handle me.");
            System.out.println(e.getMessage());
        }
     }
 
}

