using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-229175188)]
    public class TLRequestSaveTheme : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return -229175188;
            }
        }

        public TLAbsInputTheme Theme { get; set; }
        public bool Unsave { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Theme = (TLAbsInputTheme)ObjectUtils.DeserializeObject(br);
            Unsave = BoolUtil.Deserialize(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Theme, bw);
            BoolUtil.Serialize(Unsave, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
