using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Photos
{
    [TLObject(-256159406)]
    public class TLRequestUpdateProfilePhoto : TLMethod<TLAbsUserProfilePhoto>
    {
        public override int Constructor
        {
            get
            {
                return -256159406;
            }
        }

        public TLAbsInputPhoto Id { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Id = (TLAbsInputPhoto)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Id, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLAbsUserProfilePhoto)ObjectUtils.DeserializeObject(br);
        }
    }
}
