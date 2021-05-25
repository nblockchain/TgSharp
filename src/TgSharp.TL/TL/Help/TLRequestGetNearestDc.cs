using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Help
{
    [TLObject(531836966)]
    public class TLRequestGetNearestDc : TLMethod<TLNearestDc>
    {
        public override int Constructor
        {
            get
            {
                return 531836966;
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
            Response = (TLNearestDc)ObjectUtils.DeserializeObject(br);
        }
    }
}
