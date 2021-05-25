using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-323339813)]
    public class TLRequestVerifyEmail : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return -323339813;
            }
        }

        public string Email { get; set; }
        public string Code { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Email = StringUtil.Deserialize(br);
            Code = StringUtil.Deserialize(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            StringUtil.Serialize(Email, bw);
            StringUtil.Serialize(Code, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
