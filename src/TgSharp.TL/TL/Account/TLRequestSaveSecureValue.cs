using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-1986010339)]
    public class TLRequestSaveSecureValue : TLMethod<TLSecureValue>
    {
        public override int Constructor
        {
            get
            {
                return -1986010339;
            }
        }

        public TLInputSecureValue Value { get; set; }
        public long SecureSecretId { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Value = (TLInputSecureValue)ObjectUtils.DeserializeObject(br);
            SecureSecretId = br.ReadInt64();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Value, bw);
            bw.Write(SecureSecretId);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLSecureValue)ObjectUtils.DeserializeObject(br);
        }
    }
}
