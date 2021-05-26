using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Messages
{
    [TLObject(1673946374)]
    public class TLRequestGetMessages : TLMethod<Messages.TLAbsMessages>
    {
        public override int Constructor
        {
            get
            {
                return 1673946374;
            }
        }

        public TLVector<TLAbsInputMessage> Id { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Id = (TLVector<TLAbsInputMessage>)ObjectUtils.DeserializeVector<TLAbsInputMessage>(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Id, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Messages.TLAbsMessages)ObjectUtils.DeserializeObject(br);
        }
    }
}
