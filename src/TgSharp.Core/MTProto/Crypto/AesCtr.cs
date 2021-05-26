using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace TgSharp.Core.MTProto.Crypto
{
    /*
     * AES-256-CTR Implementation 
     * Original implementation by OpenSSL, ported to C#
     */
    public class AesCtr
    {
        // The input encrypted as though 128bit counter mode is being used.  The extra
        // state information to record how much of the 128bit block we have used is
        // contained in number, and the encrypted counter is kept in encryptedCount.  Both
        // *num and ecount_buf must be initialised with zeros before the first call to
        // CRYPTO_ctr128_encrypt().
        //
        // This algorithm assumes that the counter is in the x lower bits of the IV
        // (ivec), and that the application has full control over overflow and the rest
        // of the IV.  This implementation takes NO responsibility for checking that
        // the counter doesn't overflow into the rest of the IV when incremented.

        public static void Ctr128Encrypt(byte[] input, byte[] key, ref byte[] ivec, ref byte[] encryptedCount, ref int number, byte[] output)
        {
            int n;
            n = number;

            int outputPos = 0, inputPos = 0;
            int len = input.Length;

            while (n != 0 && len != 0)
            {
                output[outputPos++] = (byte)(input[inputPos++] ^ encryptedCount[n]);
                --len;
                n = (n + 1) % 16;
            }

            while (len >= 16)
            {
                encryptedCount = EncryptBlock(ivec, key);
                Ctr128Inc(ivec);
                for (n = 0; n < 16; n += sizeof(ulong))
                {
                    var xoredResult = BitConverter.GetBytes(BitConverter.ToUInt64(input, inputPos + n) ^ BitConverter.ToUInt64(encryptedCount, n));
                    Buffer.BlockCopy(xoredResult, 0, output, outputPos + n, 8);
                }
                len -= 16;
                outputPos += 16;
                inputPos += 16;
                n = 0;
            }

            if (len != 0)
            {
                encryptedCount = EncryptBlock(ivec, key);
                Ctr128Inc(ivec);
                while (len-- != 0)
                {
                    output[outputPos + n] = (byte)(input[inputPos + n] ^ encryptedCount[n]);
                    ++n;
                }
            }
            number = n;
        }

        // increment counter (128-bit int) by 1
        private static void Ctr128Inc(byte[] counter)
        {
            uint n = 16, c = 1;

            do
            {
                --n;
                c += counter[n];
                counter[n] = (byte)c;
                c >>= 8;
            } while (n != 0);
        }

        private static byte[] EncryptBlock(byte[] toEncrypt, byte[] key)
        {
            using (var aes = new RijndaelManaged())
            {
                aes.Key = key;
                aes.Mode = CipherMode.ECB;
                aes.Padding = PaddingMode.None;
                ICryptoTransform cTransform = aes.CreateEncryptor();
                return cTransform.TransformFinalBlock(toEncrypt, 0, toEncrypt.Length);
            }
        }
    }
}
