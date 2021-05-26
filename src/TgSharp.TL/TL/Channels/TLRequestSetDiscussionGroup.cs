using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Channels
{
    [TLObject(1079520178)]
    public class TLRequestSetDiscussionGroup : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return 1079520178;
            }
        }

        public TLAbsInputChannel Broadcast { get; set; }
        public TLAbsInputChannel Group { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Broadcast = (TLAbsInputChannel)ObjectUtils.DeserializeObject(br);
            Group = (TLAbsInputChannel)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Broadcast, bw);
            ObjectUtils.SerializeObject(Group, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
