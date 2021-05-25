using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Channels
{
    [TLObject(176122811)]
    public class TLRequestGetChannels : TLMethod<Messages.TLAbsChats>
    {
        public override int Constructor
        {
            get
            {
                return 176122811;
            }
        }

        public TLVector<TLAbsInputChannel> Id { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Id = (TLVector<TLAbsInputChannel>)ObjectUtils.DeserializeVector<TLAbsInputChannel>(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Id, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Messages.TLAbsChats)ObjectUtils.DeserializeObject(br);
        }
    }
}
