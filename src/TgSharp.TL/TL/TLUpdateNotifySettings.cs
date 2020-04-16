using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL
{
    [TLObject(-1094555409)]
    public class TLUpdateNotifySettings : TLAbsUpdate
    {
        public override int Constructor
        {
            get
            {
                return -1094555409;
            }
        }

        public TLAbsNotifyPeer Peer { get; set; }
        public TLPeerNotifySettings NotifySettings { get; set; }

        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Peer = (TLAbsNotifyPeer)ObjectUtils.DeserializeObject(br);
            NotifySettings = (TLPeerNotifySettings)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Peer, bw);
            ObjectUtils.SerializeObject(NotifySettings, bw);
        }
    }
}
