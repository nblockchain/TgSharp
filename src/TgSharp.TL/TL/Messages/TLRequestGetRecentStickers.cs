using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Messages
{
    [TLObject(1587647177)]
    public class TLRequestGetRecentStickers : TLMethod<Messages.TLAbsRecentStickers>
    {
        public override int Constructor
        {
            get
            {
                return 1587647177;
            }
        }

        public int Flags { get; set; }
        public bool Attached { get; set; }
        public int Hash { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Flags = br.ReadInt32();
            Attached = (Flags & 1) != 0;
            Hash = br.ReadInt32();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            bw.Write(Flags);
            bw.Write(Hash);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Messages.TLAbsRecentStickers)ObjectUtils.DeserializeObject(br);
        }
    }
}
