using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Messages
{
    [TLObject(94983360)]
    public class TLRequestReceivedMessages : TLMethod<TLVector<TLReceivedNotifyMessage>>
    {
        public override int Constructor
        {
            get
            {
                return 94983360;
            }
        }

        public int MaxId { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            MaxId = br.ReadInt32();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            bw.Write(MaxId);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLVector<TLReceivedNotifyMessage>)ObjectUtils.DeserializeVector<TLReceivedNotifyMessage>(br);
        }
    }
}
