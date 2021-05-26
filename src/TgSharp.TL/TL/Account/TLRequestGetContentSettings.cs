using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-1952756306)]
    public class TLRequestGetContentSettings : TLMethod<Account.TLContentSettings>
    {
        public override int Constructor
        {
            get
            {
                return -1952756306;
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
            Response = (Account.TLContentSettings)ObjectUtils.DeserializeObject(br);
        }
    }
}
