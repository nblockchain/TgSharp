using System;
using System.Linq;
using System.Security.Cryptography;
using TgSharp.Core.MTProto.Crypto;

namespace TgSharp.Core.Utils
{
    public class Helpers
    {
        private static Random random = new Random();

        public static ulong GenerateRandomUlong()
        {
            ulong rand = (((ulong)random.Next()) << 32) | ((ulong)random.Next());
            return rand;
        }

        public static long GenerateRandomLong()
        {
            long rand = (((long)random.Next()) << 32) | ((long)random.Next());
            return rand;
        }

        public static byte[] GenerateRandomBytes(int num)
        {
            byte[] data = new byte[num];
            random.NextBytes(data);
            return data;
        }

        public static AESKeyData CalcKey(byte[] authKey, byte[] msgKey, bool client)
        {
            int x = client ? 0 : 8;

            //sha256_a = SHA256 (msg_key + substr (auth_key, x, 36));
            var sha256A = SHA256(msgKey.Concat(authKey.Skip(x).Take(36)).ToArray());
            //sha256_b = SHA256 (substr (auth_key, 40+x, 36) + msg_key);
            var sha256B = SHA256(authKey.Skip(40 + x).Take(36).Concat(msgKey).ToArray());
            //aes_key = substr (sha256_a, 0, 8) + substr (sha256_b, 8, 16) + substr (sha256_a, 24, 8);
            var key = sha256A.Take(8).Concat(sha256B.Skip(8).Take(16)).Concat(sha256A.Skip(24).Take(8)).ToArray();
            //aes_iv = substr (sha256_b, 0, 8) + substr (sha256_a, 8, 16) + substr (sha256_b, 24, 8);
            var iv = sha256B.Take(8).Concat(sha256A.Skip(8).Take(16)).Concat(sha256B.Skip(24).Take(8)).ToArray();


            return new AESKeyData(key, iv);
        }

        public static byte[] CalcMsgKey(byte[] authKey, byte[] data)
        {
            //msg_key_large = SHA256 (substr (auth_key, 88+0, 32) + plaintext + random_padding);
            var msgKeyLarge = SHA256(authKey.Skip(88).Take(32).Concat(data).ToArray());

            //msg_key = substr (msg_key_large, 8, 16);
            return msgKeyLarge.Skip(8).Take(16).ToArray();
        }

        public static byte[] SHA256(byte[] data)
        {
            using (SHA256 sha256 = new SHA256Managed())
            {
                return sha256.ComputeHash(data);
            }
        }

        public static byte[] SHA256(byte[] data, int offset, int limit)
        {
            using (SHA256 sha256 = new SHA256Managed())
            {
                return sha256.ComputeHash(data, offset, limit);
            }
        }
    }
}
