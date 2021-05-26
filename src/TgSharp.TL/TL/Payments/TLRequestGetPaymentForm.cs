using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Payments
{
    [TLObject(-1712285883)]
    public class TLRequestGetPaymentForm : TLMethod<Payments.TLPaymentForm>
    {
        public override int Constructor
        {
            get
            {
                return -1712285883;
            }
        }

        public int MsgId { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            MsgId = br.ReadInt32();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            bw.Write(MsgId);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Payments.TLPaymentForm)ObjectUtils.DeserializeObject(br);
        }
    }
}
