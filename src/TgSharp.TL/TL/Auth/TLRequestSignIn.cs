using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Auth
{
    [TLObject(-1126886015)]
    public class TLRequestSignIn : TLMethod<Auth.TLAbsAuthorization>
    {
        public override int Constructor
        {
            get
            {
                return -1126886015;
            }
        }

        public string PhoneNumber { get; set; }
        public string PhoneCodeHash { get; set; }
        public string PhoneCode { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            PhoneNumber = StringUtil.Deserialize(br);
            PhoneCodeHash = StringUtil.Deserialize(br);
            PhoneCode = StringUtil.Deserialize(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            StringUtil.Serialize(PhoneNumber, bw);
            StringUtil.Serialize(PhoneCodeHash, bw);
            StringUtil.Serialize(PhoneCode, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Auth.TLAbsAuthorization)ObjectUtils.DeserializeObject(br);
        }
    }
}
