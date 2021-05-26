using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Messages
{
    [TLObject(486505992)]
    public class TLRequestGetSplitRanges : TLMethod<TLVector<TLMessageRange>>
    {
        public override int Constructor
        {
            get
            {
                return 486505992;
            }
        }



        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            // do nothing
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            // do nothing else
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLVector<TLMessageRange>)ObjectUtils.DeserializeVector<TLMessageRange>(br);
        }
    }
}
