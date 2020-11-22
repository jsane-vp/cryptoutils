using System;
using System.Buffers.Binary;
using System.Text;
using System.Numerics;
using System.Linq;
using System.Collections;
using System.Security;
using System.Security.Cryptography;

namespace CryptoUtils
{
    class Program
    {
        const int KEY_SIZE = 32;
        const int IV_SIZE = 12;
        static void Main(string[] args)
        {
            RNGCryptoServiceProvider crng = new RNGCryptoServiceProvider();

            byte[] key = new byte[KEY_SIZE];
            byte[] iv = new byte[IV_SIZE];
            string secret = "This is secret!";  
            byte[] longSecret = new byte[80];

            crng.GetBytes(key);
            crng.GetBytes(iv);

            // Test code to exercise the impl
            var aesCtrObj = new AesCtrMode(key, iv);
            byte[] encryptedBytes = new byte[1]; // to keep compiler happy
            encryptedBytes[0] = 0;
            for (int i = 0; i < 50; i++)
            {
                encryptedBytes = aesCtrObj.Encrypt(longSecret);
                Console.WriteLine("Size of encrypted buffer: {0}", encryptedBytes.Length);
                PrintHex(encryptedBytes);
            }

            var encShortSecret = aesCtrObj.Encrypt(Encoding.ASCII.GetBytes(secret));
            Console.WriteLine("Size of encrypted buffer: {0}", encShortSecret.Length);
            PrintHex(encShortSecret);

            // The decrypt operations should work with the object using
            // for encryptions. Replace the aesDecCtrObj with aesCtrObj.
            var aesDecCtrObj = new AesCtrMode(key, iv);
            byte[] orgSecret = aesDecCtrObj.Decrypt(encShortSecret);
            Console.WriteLine(Encoding.Default.GetString(orgSecret));

            byte[] clearText = aesDecCtrObj.Decrypt(encryptedBytes);
            PrintHex(clearText);
        }

        public static void PrintHex(byte[] toPrint)
        {
            // Not the most perfect way to do this but ...
            char[] c = new char[toPrint.Length * 2 ];
            byte b;
            for (int i = 0; i < toPrint.Length; ++i)
            {
                b = ((byte)(toPrint[i] >> 4));
                c[i * 2] = (char)(b > 9 ? b + 0x37 : b + 0x30);
                b = ((byte)(toPrint[i] & 0xF));
                c[i * 2 + 1] = (char)(b > 9 ? b + 0x37 : b + 0x30);
            }
            Console.WriteLine(new string(c));
        }
    }

   // C# implementation of AES counter mode with authentication
   // This code can be made more tighter and perhaps optimized at places.
   // I have erred on side of correctness & safety than using any unsafe optimizations
   // since I am not a C# expert.
   // Also missing are some defensive validation checks at places.

   // The authentication support is not perfect but should be a reasonable
   // compromise. It should discourage most casual chosen-plaintext attacks.
   // See comments in ComputeHmac method.

   // One motivation was to have an easier to use implementation than
   // say .Net's AesCcm which requires caller to keep track of the nonce
   // which must be unique for every piece of data and the tags.   
   // The generated cipher text is self contained. One just needs to 
   // instantiate the class with a key and an IV.
    public  class AesCtrMode
    {
        #region class variables
        const int IV_COUNTER_SIZE = 16;
        const int BLOCK_SIZE = 16;
        const int MINI_HASH = 4; 
        
        private byte[] _key;

        // must be unique for every key
        private byte[] _ba_ivCtrEncrypt;   // used during encryption
        private int _ctr; // internal counter
        private byte[] _ba_ivCtrDecrypt; // used during decryption 

        private BigInteger _bi_ivCtrEncrypt, _bi_ivCtrDecrypt;

        AesManaged _aesObj;
        ICryptoTransform _encryptor;
        #endregion

        public AesCtrMode(byte[] key, byte[] iv)
        {
            // TODO:: Ensure the incoming key is 256 bits and IV is of 96 bit size
	    // There is nothing preventing you from using 128, 192 sized keys.
	    // Except the hash computation makes an assumption on key to be 256 bits.
            _key = new byte[key.Length];
            Buffer.BlockCopy(key, 0, _key, 0, key.Length);

            // Big integer treats the first byte as LSB and will 
            // increment from there. We want the counter portion
            // to increment so counter is kept in the first four bytes.
            _ba_ivCtrEncrypt = new byte[iv.Length + sizeof(int)];
            _ba_ivCtrDecrypt = new byte[iv.Length + sizeof(int)];
            _ctr = 0;
            
            Buffer.BlockCopy(iv, 0, _ba_ivCtrEncrypt, sizeof(int), iv.Length);
            Buffer.BlockCopy(iv, 0, _ba_ivCtrDecrypt, sizeof(int), iv.Length);
            init();
        }

        private void init()
        {
            _aesObj = new AesManaged();
            _aesObj.Mode = CipherMode.ECB;
            _aesObj.Padding = PaddingMode.None;
            _aesObj.Key = _key;
            _aesObj.IV = new byte[IV_COUNTER_SIZE]; // zero IV

            _encryptor = _aesObj.CreateEncryptor();
            
            _bi_ivCtrEncrypt = new BigInteger(_ba_ivCtrEncrypt);
        }

        private void encNIncCounter(ref BigInteger ivCounter, ref byte[] encryptedIVCtr)
        {
            _encryptor.TransformBlock(ivCounter.ToByteArray(), 0, IV_COUNTER_SIZE, 
                                        encryptedIVCtr, 0);
            // Advance the counter.
            ivCounter++;

            // We support a max of 0x7FFF (32,767) counter value for a given IV value.
            // The cardinal rule for CTR mode operation is the IV+counter must
            // be unique for every data block with a given key value.
            // Once it reaches this threshold we will throw an exception to disallow 
            // use of this construct (key and IV)
            // This translates into a maximum of 16 * 32,767 bytes of data one can encrypt
            // OR 32,767 distinct pieces of data smaller than 16 bytes in size. 
            _ctr++;
            if (_ctr > 0x7FFF)
                throw new CryptographicException("Max counter reached for this key, iv combination.\nUse a different IV and/or key");
        }

        // Encodes the current value of the "counter" portion in a compact format
        // that can be prefixed to encrypted bytes so it is available during decryption. 
        private byte[] encodeCounter()
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
            byte[] ctrBytes = new byte[4];
            Span<byte> bb = new Span<byte>(ctrBytes);

            BinaryPrimitives.WriteInt32BigEndian(bb, _ctr);

            int i = 0;
            while ( (i < sizeof(int) - 1) && (ctrBytes[i] == 0) )
                i++;
            if ( (i == sizeof(int)-1) && (ctrBytes[i] >= 0x80) )
                i--;                            
            byte[] encodedCtrBytes = ctrBytes[i..];
            if (encodedCtrBytes.Length > 1)
                encodedCtrBytes[0] |= 0x80;

            return encodedCtrBytes;        
        }

        // Returns the counter value as an integer
        private int decodeCounter(byte[] encodedCounter)
        {
            byte[] intSizeCounter = new byte[sizeof(int)];
            Buffer.BlockCopy(encodedCounter, 0, intSizeCounter, 
                                    sizeof(int) - encodedCounter.Length,
                                    encodedCounter.Length );
            Span<byte> ctrSpanBytes = new Span<byte>(intSizeCounter);

            // We take the big endian encoded byte array
            // Mask off the MSB bit and turn it into a integer
            // for adding it to a BigInteger housing IV portion
            intSizeCounter[sizeof(int) - encodedCounter.Length] &= 0x7F;

            int counterValue = BinaryPrimitives.ReadInt32BigEndian(ctrSpanBytes);

            return counterValue;
        }

        // Results will be stored in target block (will lose original contents)
        private void xorBlock(ref byte[] targetBlock, byte[] srcBlock)
        {
            BitArray tBA = new BitArray(targetBlock);
            BitArray sBA = new BitArray(srcBlock);

            tBA.Xor(sBA);
            tBA.CopyTo(targetBlock, 0);
        }

        // Returns the cipher or plain text.
        // Must be initialized with a key and an IV
        // Note that the counter portion of the IV, as maintained
        // by the instance of the class, increases with every encryption operation 

        // Encrypt operation will encode the counter
        // Decrypt operation will decode the counter required for decryption
        private byte[] encryptOrDecrypt(bool encrypt, byte[] inputBytes)
        {
            byte[] counterBytes;
            byte[] outputBytes;
            int srcPos;
            int targetPos;
            int bytesRemaining;
            BigInteger bgIvCtrToUse;
            byte[] encryptedIvCtrBuffer = new byte[IV_COUNTER_SIZE];

            byte[] encBlock = new byte[BLOCK_SIZE];

            if (_aesObj == null)
                throw new CryptographicException("Uninitialized cipher");

            if (encrypt)
            {
                // IMPORTANT to get the starting counter value before it is incremented
                counterBytes = encodeCounter();
                srcPos = 0;
                targetPos = counterBytes.Length; // encrypted bytes come after encoded counter
                bytesRemaining = inputBytes.Length;
                outputBytes = new byte[counterBytes.Length + inputBytes.Length];

                // Write the encoded (starting) counter value to the buffer housing cipher text.
                Buffer.BlockCopy(counterBytes, 0, outputBytes, 0, counterBytes.Length);

                bgIvCtrToUse = _bi_ivCtrEncrypt;
            }
            else // decryption
            {
                // Extract the encoded counter from the cipherText
                int ctrBytesSize = (int)((inputBytes[0] & 0x80) >> 7) + 1;
                byte[] ctrBytes = new byte[ctrBytesSize];
                Buffer.BlockCopy(inputBytes, 0, ctrBytes, 0, ctrBytesSize);
                
                srcPos = ctrBytesSize;
                targetPos = 0;
                bytesRemaining = inputBytes.Length - ctrBytesSize;
                
                int counterValue = decodeCounter(ctrBytes);
                _bi_ivCtrDecrypt = new BigInteger(_ba_ivCtrDecrypt);

                // Add (append) the counter to the IV
                _bi_ivCtrDecrypt += counterValue;

                outputBytes = new byte[inputBytes.Length - ctrBytesSize];

                bgIvCtrToUse = _bi_ivCtrDecrypt;
            }

            while (bytesRemaining >= BLOCK_SIZE) {
                encNIncCounter(ref bgIvCtrToUse, ref encryptedIvCtrBuffer);
                Buffer.BlockCopy(inputBytes, srcPos, encBlock, 0, BLOCK_SIZE);
                xorBlock(ref encBlock, encryptedIvCtrBuffer);
                Buffer.BlockCopy(encBlock, 0, outputBytes, targetPos, BLOCK_SIZE);
                srcPos += BLOCK_SIZE;
                targetPos += BLOCK_SIZE;
                bytesRemaining -= BLOCK_SIZE;
            }

            if (bytesRemaining > 0)
            {
                Array.Resize(ref encBlock, bytesRemaining);
                byte[] choppedIvCtr = new byte[bytesRemaining];

                encNIncCounter(ref bgIvCtrToUse, ref encryptedIvCtrBuffer);
                Buffer.BlockCopy(inputBytes, srcPos, encBlock, 0, bytesRemaining);
                Array.Resize(ref encryptedIvCtrBuffer, bytesRemaining);

                xorBlock(ref encBlock, encryptedIvCtrBuffer);
                Buffer.BlockCopy(encBlock, 0, outputBytes, targetPos, bytesRemaining);
            }

            // Ensure the counter maintained as part of the state is updated. 
            if (encrypt)
                _bi_ivCtrEncrypt = bgIvCtrToUse;
            else
                _bi_ivCtrDecrypt = bgIvCtrToUse;

            return outputBytes;
        }

        // HMAC is computed using the same key over 
        // <cipherText + IV>
        private byte[] ComputeHmac(byte[] cipherText)
        {
            // TODO::
            // We could flip the key around when using for HMAC
            // as a precautionary measure.
            HMACSHA256 hMac = new HMACSHA256(_key);

            byte[] computedHmac, interimHmac;
            int orgCipherTxtLen = cipherText.Length;
            int hashInSize = cipherText.Length + _ba_ivCtrEncrypt.Length - sizeof(int);
            // The IV portion is same for both encrypt & decrypt
            // byte[] hashInput = new byte [hashInSize];

            Array.Resize(ref cipherText, hashInSize);

            // Remember the IV is after the counter bytes (sizeof int)
            Buffer.BlockCopy(_ba_ivCtrEncrypt, sizeof(int), 
                                cipherText, orgCipherTxtLen, 
                                _ba_ivCtrEncrypt.Length - sizeof(int));
            interimHmac = hMac.ComputeHash(cipherText);

            // We do a recursive hmac over the above to compensate for 
            // the fidelity loss when using truncated HMAC.
            computedHmac = hMac.ComputeHash(interimHmac);
            
            Array.Resize(ref computedHmac, MINI_HASH);
            Array.Resize(ref cipherText, orgCipherTxtLen);
            
            return computedHmac; 
        }

        // Authenticated counter mode of operation.
        // Cipher text is of same length as that of plain text but carries this
        // additional meta data:
        //    - encoded counter value (prefixed - max 2 bytes)
        //    - 4 bytes of hmac digest appended
        public byte[] Encrypt(byte[] plainText)
        {
            byte[] cipherText, hMac;
            int orgCipherTxtLen;

            cipherText = encryptOrDecrypt(true, plainText);

            // Hmac is over cipherText and the IV. 
            // cipher text already encodes counter
            hMac = ComputeHmac(cipherText);

            orgCipherTxtLen = cipherText.Length;

            // Append the hmac to the cipherText
            Array.Resize(ref cipherText, cipherText.Length + hMac.Length);
            Buffer.BlockCopy(hMac, 0, cipherText, orgCipherTxtLen, hMac.Length);

            return cipherText;
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            byte[] computedHmac, givenHmac;
            byte[] plainText;

            // Verify the integrity of supplied cipher text against the key and IV.
            givenHmac = new byte[MINI_HASH];
            Buffer.BlockCopy(cipherText, cipherText.Length - MINI_HASH, givenHmac, 0, MINI_HASH);
            Array.Resize(ref cipherText, cipherText.Length - MINI_HASH);
            computedHmac = ComputeHmac(cipherText);
            for (int i=0; i < MINI_HASH; i++)
                if (computedHmac[i] != givenHmac[i])
                    throw new CryptographicException("Tampered cipherText or wrong IV or key detected");

            plainText = encryptOrDecrypt(false, cipherText);
            return plainText;
        }

    }
    
}
