using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-1199522741)]
    public class TLRequestDeleteSecureValue : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return -1199522741;
            }
        }

        public TLVector<TLAbsSecureValueType> Types { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Types = (TLVector<TLAbsSecureValueType>)ObjectUtils.DeserializeVector<TLAbsSecureValueType>(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Types, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
