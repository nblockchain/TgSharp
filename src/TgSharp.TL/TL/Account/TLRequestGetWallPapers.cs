using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-1430579357)]
    public class TLRequestGetWallPapers : TLMethod<Account.TLAbsWallPapers>
    {
        public override int Constructor
        {
            get
            {
                return -1430579357;
            }
        }

        public int Hash { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Hash = br.ReadInt32();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            bw.Write(Hash);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Account.TLAbsWallPapers)ObjectUtils.DeserializeObject(br);
        }
    }
}
