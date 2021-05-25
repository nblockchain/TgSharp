using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Stickers
{
    [TLObject(-4795190)]
    public class TLRequestChangeStickerPosition : TLMethod<Messages.TLStickerSet>
    {
        public override int Constructor
        {
            get
            {
                return -4795190;
            }
        }

        public TLAbsInputDocument Sticker { get; set; }
        public int Position { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            Sticker = (TLAbsInputDocument)ObjectUtils.DeserializeObject(br);
            Position = br.ReadInt32();
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            ObjectUtils.SerializeObject(Sticker, bw);
            bw.Write(Position);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (Messages.TLStickerSet)ObjectUtils.DeserializeObject(br);
        }
    }
}
