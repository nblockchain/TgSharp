using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-2108208411)]
    public class TLRequestSendChangePhoneCode : TLMethod<Auth.TLSentCode>
    {
        public override int Constructor
        {
            get
            {
                return -2108208411;
            }
        }

        public string PhoneNumber { get; set; }
        public TLCodeSettings Settings { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            PhoneNumber = StringUtil.Deserialize(br);
            Settings = (TLCodeSettings)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            StringUtil.Serialize(PhoneNumber, bw);
            ObjectUtils.SerializeObject(Settings, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Auth.TLSentCode)ObjectUtils.DeserializeObject(br);
        }
    }
}
