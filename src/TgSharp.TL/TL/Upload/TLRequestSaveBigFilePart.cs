using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Upload
{
    [TLObject(-562337987)]
    public class TLRequestSaveBigFilePart : TLMethod<bool>
    {
        public override int Constructor
        {
            get
            {
                return -562337987;
            }
        }

        public long FileId { get; set; }
        public int FilePart { get; set; }
        public int FileTotalParts { get; set; }
        public byte[] Bytes { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            FileId = br.ReadInt64();
            FilePart = br.ReadInt32();
            FileTotalParts = br.ReadInt32();
            Bytes = BytesUtil.Deserialize(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            bw.Write(FileId);
            bw.Write(FilePart);
            bw.Write(FileTotalParts);
            BytesUtil.Serialize(Bytes, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = BoolUtil.Deserialize(br);
        }
    }
}
