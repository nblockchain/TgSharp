using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Help
{
    [TLObject(749019089)]
    public class TLRequestGetTermsOfServiceUpdate : TLMethod<Help.TLAbsTermsOfServiceUpdate>
    {
        public override int Constructor
        {
            get
            {
                return 749019089;
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
            Response = (Help.TLAbsTermsOfServiceUpdate)ObjectUtils.DeserializeObject(br);
        }
    }
}
