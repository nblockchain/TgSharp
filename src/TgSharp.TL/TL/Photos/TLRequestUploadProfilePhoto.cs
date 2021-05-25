using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Photos
{
    [TLObject(1328726168)]
    public class TLRequestUploadProfilePhoto : TLMethod<Photos.TLPhoto>
    {
        public override int Constructor
        {
            get
            {
                return 1328726168;
            }
        }

        public TLAbsInputFile File { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            File = (TLAbsInputFile)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(File, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Photos.TLPhoto)ObjectUtils.DeserializeObject(br);
        }
    }
}
