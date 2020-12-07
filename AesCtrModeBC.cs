using System;
using System.Buffers.Binary;
using System.Text;
using System.Numerics;
using System.Linq;
using System.Collections;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;

using System.Globalization;
using System.Security.Cryptography;

namespace AesCtrModeBC
{
    // Utility wrapper class around Bouncy Castle's AES CTR mode impl.
    // Keeps track of the counter and the cipher text is authenticated.
    // Requires you to supply a key and in IV.

    // You need to add a reference to BouncyCastle package using this
    // dotnet add package BouncyCastle 
    // to build the code.

    public class AesCtrModeBC
    {
        #region class variables
        const int IV_COUNTER_SIZE = 16; // in bytes

        const int IV_SIZE = 12; // in bytes
        const int BLOCK_SIZE = 16;
        const int MINI_HASH = 4; 

        // TODO: Obsecure this when held in memory
        // Or change the design to not require keeping it in memory for 
        // the life of the class.        
        private byte[] _key;

        // must be unique for every key
        private byte[] _ba_ivCtrEncrypt;   // used during encryption
        private int _ctr; // internal counter
        private byte[] _ba_ivCtrDecrypt; // used during decryption 

        private BigInteger _bi_ivCtrEncrypt, _bi_ivCtrDecrypt;

        IBufferedCipher _aesEncObj, _aesDecObj;
        #endregion

        public AesCtrModeBC(byte[] key, byte[] iv)
        {
            // TODO:: Ensure the incoming key is 256 bits and IV is of 96 bit size
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
            // Initialize AES CTR (counter) mode cipher from the BouncyCastle cryptography library
            _aesEncObj = CipherUtilities.GetCipher("AES/CTR/NoPadding");
            _aesDecObj = CipherUtilities.GetCipher("AES/CTR/NoPadding");

            _bi_ivCtrEncrypt = new BigInteger(_ba_ivCtrEncrypt);
        }


        // TODO:: Simplify the encode and decode methods (since the counter is only two bytes max).

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

        private byte[] encrypt(byte[] toEncrypt)
        {
            byte[] counterBytes = encodeCounter();

            // Note the current counter and encode it
            _aesEncObj.Init(true, 
                        new ParametersWithIV(
                            ParameterUtilities.CreateKeyParameter("AES", _key), 
                                    _bi_ivCtrEncrypt.ToByteArray() ));

            byte[] cipherText = _aesEncObj.DoFinal(toEncrypt);

            byte[] ctrPlusCipherText = new byte[counterBytes.Length +
                                                cipherText.Length];
            Buffer.BlockCopy(counterBytes, 0, 
                            ctrPlusCipherText, 0,
                             counterBytes.Length);
            Buffer.BlockCopy(cipherText, 0, ctrPlusCipherText,
                                counterBytes.Length,
                                cipherText.Length);

            // IMPORTANT: Increment the counter along with the IV+Counter
            // by appropriate number of 16 byte blocks
            _ctr += (toEncrypt.Length / 16) + 1;
            _bi_ivCtrEncrypt += (toEncrypt.Length / 16) + 1;

            return ctrPlusCipherText;
        }

        private byte[] decrypt(byte[] toDec)
        {
            byte[] ctrBytes = new byte[ (int)(toDec[0] >> 7) + 1];
            int counterValue;
            byte[] justCipherTxt;
            
            Buffer.BlockCopy(toDec, 0, ctrBytes, 0, ctrBytes.Length);
            counterValue = decodeCounter(ctrBytes);

            justCipherTxt = new byte[toDec.Length - ctrBytes.Length];
            Buffer.BlockCopy(toDec, ctrBytes.Length, justCipherTxt, 0,
                            justCipherTxt.Length);

            // Combine counter and IV
            _bi_ivCtrDecrypt = new BigInteger(_ba_ivCtrDecrypt);
            _bi_ivCtrDecrypt += counterValue;

            _aesDecObj.Init(true, 
                        new ParametersWithIV(
                            ParameterUtilities.CreateKeyParameter("AES", _key), 
                                    _bi_ivCtrDecrypt.ToByteArray() ));

            return _aesDecObj.DoFinal(justCipherTxt);
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

            Array.Resize(ref cipherText, hashInSize);

            // The IV portion is same for both encrypt & decrypt
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

        public byte[] Encrypt(byte[] clearBytes)
        {
            int orgCipherTxtLen;

            byte[] ctrPlusCipherText = encrypt(clearBytes);
            byte[] hMac = ComputeHmac(ctrPlusCipherText);

            orgCipherTxtLen = ctrPlusCipherText.Length;

            // Append the hmac to the cipherText
            Array.Resize(ref ctrPlusCipherText, ctrPlusCipherText.Length + hMac.Length);
            Buffer.BlockCopy(hMac, 0, ctrPlusCipherText, orgCipherTxtLen, hMac.Length);

            return ctrPlusCipherText;
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

            plainText = decrypt(cipherText);
            return plainText;
        }

    }

    class Program
    {
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

        static void Main(string[] args)
        {
            RNGCryptoServiceProvider crng = new RNGCryptoServiceProvider();
            
            string inputString = "This is a secret";
            byte[] inputBytes;
            
            inputBytes = ASCIIEncoding.UTF8.GetBytes(inputString);

            byte[] key = new byte[32]; // 256 bit key
            byte[] iv = new byte[12]; // 96 bit iv gets combined with 32 byte counter

            crng.GetBytes(key);
            crng.GetBytes(iv);

            AesCtrModeBC acm = new AesCtrModeBC(key, iv);
            byte[] cipherText, clearText;
            cipherText = acm.Encrypt(inputBytes);

            for (int i=0; i<25; i++)
            {
                cipherText = acm.Encrypt(inputBytes);

                // Uncomment these lines if you are interested in seeing the
                // cipher text and decrypted version in each iteration...

                // Program.PrintHex(cipherText);
                // clearText = acm.Decrypt(cipherText);
                // Console.WriteLine(Encoding.UTF8.GetString(clearText));
            }

            Program.PrintHex(cipherText);
            clearText = acm.Decrypt(cipherText);
            Program.PrintHex(clearText);
            Console.WriteLine(Encoding.UTF8.GetString(clearText));
        }
    }

}