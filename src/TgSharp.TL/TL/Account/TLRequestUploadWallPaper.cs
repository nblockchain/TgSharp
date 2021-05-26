using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-578472351)]
    public class TLRequestUploadWallPaper : TLMethod<TLAbsWallPaper>
    {
        public override int Constructor
        {
            get
            {
                return -578472351;
            }
        }

        public TLAbsInputFile File { get; set; }
        public string MimeType { get; set; }
        public TLWallPaperSettings Settings { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            File = (TLAbsInputFile)ObjectUtils.DeserializeObject(br);
            MimeType = StringUtil.Deserialize(br);
            Settings = (TLWallPaperSettings)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(File, bw);
            StringUtil.Serialize(MimeType, bw);
            ObjectUtils.SerializeObject(Settings, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLAbsWallPaper)ObjectUtils.DeserializeObject(br);
        }
    }
}
