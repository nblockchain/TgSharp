using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Contacts
{
    [TLObject(451113900)]
    public class TLRequestResetTopPeerRating : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return 451113900;
            }
        }

        public TLAbsTopPeerCategory Category { get; set; }
        public TLAbsInputPeer Peer { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Category = (TLAbsTopPeerCategory)ObjectUtils.DeserializeObject(br);
            Peer = (TLAbsInputPeer)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Category, bw);
            ObjectUtils.SerializeObject(Peer, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
