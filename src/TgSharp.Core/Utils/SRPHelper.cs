using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Xml.Serialization;
using TgSharp.Core.MTProto.Crypto;
using TgSharp.TL;
using TgSharp.TL.Account;

namespace TgSharp.Core.Utils
{
    public static class SRPHelper
    {
        public static async Task<TLInputCheckPasswordSRP> CheckPassword(this TelegramClient client, string password, CancellationToken token = default)
        {
            var passwordSettings = await client.SendRequestAsync<TLPassword>(new TLRequestGetPassword { }, token);

            var algoSettings = passwordSettings.CurrentAlgo as TLPasswordKdfAlgoSHA256SHA256PBKDF2HMACSHA512iter100000SHA256ModPow;
            if (algoSettings == null)
                throw new NotImplementedException();

            var passwordInBytes = Encoding.UTF8.GetBytes(password);

            var PrivateKey = new BigInteger(1, PH2(passwordInBytes, algoSettings.Salt1, algoSettings.Salt2));
            var Generator = BigInteger.ValueOf(algoSettings.G);
            var Prime = new BigInteger(1, algoSettings.P);

            var gForHash = PadBigNumForHash(Generator);
            var pForHash = PadBytesForHash(algoSettings.P);

            //Random prime number 
            var Random = RandomNumberGenerator.Create();
            var RandomBytes = new byte[256];
            Random.GetBytes(RandomBytes);

            var G_X = Generator.ModPow(PrivateKey, Prime);
            var K = new BigInteger(1, H(pForHash, gForHash));
            var KG_X = K.Multiply(G_X).Mod(Prime);

            var A = new BigInteger(1, RandomBytes.ToArray());
            var GA = Generator.ModPow(A, Prime);
            var GAForHash = PadBigNumForHash(GA);
            var GB = new BigInteger(1, passwordSettings.SrpB);
            var GBForHash = PadBytesForHash(passwordSettings.SrpB);

            var U = new BigInteger(1, H(GAForHash, GBForHash));

            
            var T = (GB.Subtract(KG_X)).Mod(Prime);
            var S = T.ModPow(U.Multiply(PrivateKey).Add(A), Prime);
            var K_A = H(PadBytesForHash(S.ToByteArrayUnsigned()));
            var M1 = H(XOR(H(pForHash), H(gForHash)),
                        H(algoSettings.Salt1),
                        H(algoSettings.Salt2),
                        GAForHash,
                        GBForHash,
                        K_A
                    );

            return new TLInputCheckPasswordSRP
            {
                A = GAForHash,
                M1 = M1,
                SrpId = passwordSettings.SrpId.Value
            };
        }

        #region Hashing Functions
        private static byte[] H(params byte[][] data)
        {
            using (SHA256Managed sha256 = new SHA256Managed())
            {
                var position = 0;
                var outputArray = new byte[data.Sum(a => a.Length)];
                foreach (var curr in data)
                {
                    Array.Copy(curr, 0, outputArray, position, curr.Length);
                    position += curr.Length;
                }
                return sha256.ComputeHash(outputArray);
            }
        }
        private static byte[] Pbkdf2(byte[] password, byte[] salt, int iterations = 100000, int hashByteSize = 64)
        {
            var pdb = new Pkcs5S2ParametersGenerator(new Org.BouncyCastle.Crypto.Digests.Sha512Digest());
            pdb.Init(password, salt,
                         iterations);
            var key = (KeyParameter)pdb.GenerateDerivedMacParameters(hashByteSize * 8);
            return key.GetKey();
        }
        private static byte[] SH(byte[] data, byte[] salt) => H(salt, data, salt);
        private static byte[] PH1(byte[] data, byte[] salt1, byte[] salt2) => SH(SH(data, salt1), salt2);
        private static byte[] PH2(byte[] password, byte[] salt1, byte[] salt2) => SH(Pbkdf2(PH1(password, salt1, salt2), salt1), salt2);
        #endregion
        #region Padding Functions
        private static byte[] PadBytesForHash(byte[] data)
        {
            return new byte[256 - data.Length].Concat(data).ToArray();
        }
        private static byte[] PadBigNumForHash(BigInteger number)
        {
            var data = number.ToByteArrayUnsigned();
            return new byte[256 - data.Length].Concat(data).ToArray();
        }
        #endregion
        #region Computational Functions
        public static byte[] XOR(byte[] arr1, byte[] arr2)
        {
            if (arr1.Length != arr2.Length)
                throw new ArgumentException("arr1 and arr2 are not the same length");

            byte[] result = new byte[arr1.Length];

            for (int i = 0; i < arr1.Length; ++i)
                result[i] = (byte)(arr1[i] ^ arr2[i]);

            return result;
        }
        #endregion


    }
}

