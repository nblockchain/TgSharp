using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Contacts
{
    [TLObject(-995929106)]
    public class TLRequestGetStatuses : TLMethod<TLVector<TLContactStatus>>
    {
        public override int Constructor
        {
            get
            {
                return -995929106;
            }
        }



        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            // do nothing
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            // do nothing else
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLVector<TLContactStatus>)ObjectUtils.DeserializeVector<TLContactStatus>(br);
        }
    }
}
