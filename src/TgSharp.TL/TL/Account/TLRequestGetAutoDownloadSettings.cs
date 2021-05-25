using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(1457130303)]
    public class TLRequestGetAutoDownloadSettings : TLMethod<Account.TLAutoDownloadSettings>
    {
        public override int Constructor
        {
            get
            {
                return 1457130303;
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
            Response = (Account.TLAutoDownloadSettings)ObjectUtils.DeserializeObject(br);
        }
    }
}
