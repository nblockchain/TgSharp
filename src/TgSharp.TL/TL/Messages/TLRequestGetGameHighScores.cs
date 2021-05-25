using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Messages
{
    [TLObject(-400399203)]
    public class TLRequestGetGameHighScores : TLMethod<Messages.TLHighScores>
    {
        public override int Constructor
        {
            get
            {
                return -400399203;
            }
        }

        public TLAbsInputPeer Peer { get; set; }
        public int Id { get; set; }
        public TLAbsInputUser UserId { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Peer = (TLAbsInputPeer)ObjectUtils.DeserializeObject(br);
            Id = br.ReadInt32();
            UserId = (TLAbsInputUser)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Peer, bw);
            bw.Write(Id);
            ObjectUtils.SerializeObject(UserId, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Messages.TLHighScores)ObjectUtils.DeserializeObject(br);
        }
    }
}
