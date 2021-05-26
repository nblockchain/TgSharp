using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(1880182943)]
    public class TLRequestSendVerifyEmailCode : TLMethod<Account.TLSentEmailCode>
    {
        public override int Constructor
        {
            get
            {
                return 1880182943;
            }
        }

        public string Email { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Email = StringUtil.Deserialize(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            StringUtil.Serialize(Email, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Account.TLSentEmailCode)ObjectUtils.DeserializeObject(br);
        }
    }
}
