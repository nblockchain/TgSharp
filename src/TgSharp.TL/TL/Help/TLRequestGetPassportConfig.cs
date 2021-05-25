using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Help
{
    [TLObject(-966677240)]
    public class TLRequestGetPassportConfig : TLMethod<Help.TLAbsPassportConfig>
    {
        public override int Constructor
        {
            get
            {
                return -966677240;
            }
        }

        public int Hash { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Hash = br.ReadInt32();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            bw.Write(Hash);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Help.TLAbsPassportConfig)ObjectUtils.DeserializeObject(br);
        }
    }
}
