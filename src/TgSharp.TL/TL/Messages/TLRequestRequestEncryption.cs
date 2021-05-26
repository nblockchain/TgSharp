using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Messages
{
    [TLObject(-162681021)]
    public class TLRequestRequestEncryption : TLMethod<TLAbsEncryptedChat>
    {
        public override int Constructor
        {
            get
            {
                return -162681021;
            }
        }

        public TLAbsInputUser UserId { get; set; }
        public int RandomId { get; set; }
        public byte[] GA { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            UserId = (TLAbsInputUser)ObjectUtils.DeserializeObject(br);
            RandomId = br.ReadInt32();
            GA = BytesUtil.Deserialize(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(UserId, bw);
            bw.Write(RandomId);
            BytesUtil.Serialize(GA, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLAbsEncryptedChat)ObjectUtils.DeserializeObject(br);
        }
    }
}
