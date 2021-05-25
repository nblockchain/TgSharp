using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Account
{
    [TLObject(-18000023)]
    public class TLRequestInstallWallPaper : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return -18000023;
            }
        }

        public TLAbsInputWallPaper Wallpaper { get; set; }
        public TLWallPaperSettings Settings { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Wallpaper = (TLAbsInputWallPaper)ObjectUtils.DeserializeObject(br);
            Settings = (TLWallPaperSettings)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Wallpaper, bw);
            ObjectUtils.SerializeObject(Settings, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
