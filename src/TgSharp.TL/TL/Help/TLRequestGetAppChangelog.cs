using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Help
{
    [TLObject(-1877938321)]
    public class TLRequestGetAppChangelog : TLMethod<TLAbsUpdates>
    {
        public override int Constructor
        {
            get
            {
                return -1877938321;
            }
        }

        public string PrevAppVersion { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            PrevAppVersion = StringUtil.Deserialize(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            StringUtil.Serialize(PrevAppVersion, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLAbsUpdates)ObjectUtils.DeserializeObject(br);
        }
    }
}
