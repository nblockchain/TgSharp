using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Channels
{
    [TLObject(141781513)]
    public class TLRequestGetFullChannel : TLMethod<Messages.TLChatFull>
    {
        public override int Constructor
        {
            get
            {
                return 141781513;
            }
        }

        public TLAbsInputChannel Channel { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Channel = (TLAbsInputChannel)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Channel, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Messages.TLChatFull)ObjectUtils.DeserializeObject(br);
        }
    }
}
