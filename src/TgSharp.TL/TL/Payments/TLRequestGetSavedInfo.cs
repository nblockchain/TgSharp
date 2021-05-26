using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Payments
{
    [TLObject(578650699)]
    public class TLRequestGetSavedInfo : TLMethod<Payments.TLSavedInfo>
    {
        public override int Constructor
        {
            get
            {
                return 578650699;
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
            Response = (Payments.TLSavedInfo)ObjectUtils.DeserializeObject(br);
        }
    }
}
