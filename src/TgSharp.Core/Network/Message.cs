using System;
using System.IO;
using System.Linq;
using TgSharp.Core.MTProto.Crypto;

namespace TgSharp.Core.Network
{
    internal class Message
    {
        internal byte[] Body { get; private set; }

        internal Message(byte[] body)
        {
            if (body == null)
                throw new ArgumentNullException(nameof(body));

            Body = body;
        }

        internal static Message Decode(byte[] body)
        {
            using (var memoryStream = new MemoryStream(body))
            {
                using (var binaryReader = new BinaryReader(memoryStream))
                {
                    int length = binaryReader.ReadInt32();
                    return new Message(binaryReader.ReadBytes(length));
                }
            }
        }

        internal byte[] Encode()
        {
            using (var memoryStream = new MemoryStream())
            {
                using (var binaryWriter = new BinaryWriter(memoryStream))
                {
                    binaryWriter.Write(Body.Length);
                    binaryWriter.Write(Body);
                    return memoryStream.ToArray();
                }
            }
        }

    }
}
