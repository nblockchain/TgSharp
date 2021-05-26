using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-2067899501)]
    public class TLRequestUpdateNotifySettings : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return -2067899501;
            }
        }

        public TLAbsInputNotifyPeer Peer { get; set; }
        public TLInputPeerNotifySettings Settings { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Peer = (TLAbsInputNotifyPeer)ObjectUtils.DeserializeObject(br);
            Settings = (TLInputPeerNotifySettings)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Peer, bw);
            ObjectUtils.SerializeObject(Settings, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
