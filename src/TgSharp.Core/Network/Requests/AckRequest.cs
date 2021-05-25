using System;
using System.Collections.Generic;
using System.IO;

using TgSharp.TL;

namespace TgSharp.Core.Network.Requests
{
    public class AckRequest : TLObject
    {
        private readonly List<ulong> msgs;

        public override int Constructor => 0x62d6b459;

        public AckRequest(List<ulong> msgs)
        {
            this.msgs = msgs;
        }

        public override void SerializeBody(BinaryWriter writer)
        {
            writer.Write(0x62d6b459); // msgs_ack
            writer.Write(0x1cb5c415); // Vector
            writer.Write(msgs.Count);
            foreach (ulong messageId in msgs)
            {
                writer.Write(messageId);
            }
        }

        public override void DeserializeBody(BinaryReader reader)
        {
            throw new NotImplementedException();
        }

    }
}
