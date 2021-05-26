using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Auth
{
    [TLObject(-440401971)]
    public class TLRequestExportAuthorization : TLMethod<Auth.TLExportedAuthorization>
    {
        public override int Constructor
        {
            get
            {
                return -440401971;
            }
        }

        public int DcId { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            DcId = br.ReadInt32();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            bw.Write(DcId);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Auth.TLExportedAuthorization)ObjectUtils.DeserializeObject(br);
        }
    }
}
