using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Bots
{
    [TLObject(-1440257555)]
    public class TLRequestSendCustomRequest : TLMethod<TLDataJSON>
    {
        public override int Constructor
        {
            get
            {
                return -1440257555;
            }
        }

        public string CustomMethod { get; set; }
        public TLDataJSON Params { get; set; }


        public void ComputeFlags()
        {
            // do nothing
        }

        public override void DeserializeBody(BinaryReader br)
        {
            CustomMethod = StringUtil.Deserialize(br);
            Params = (TLDataJSON)ObjectUtils.DeserializeObject(br);
        }

        public override void SerializeBody(BinaryWriter bw)
        {
            bw.Write(Constructor);
            StringUtil.Serialize(CustomMethod, bw);
            ObjectUtils.SerializeObject(Params, bw);
        }

        protected override void DeserializeResponse(BinaryReader br)
        {
            Response = (TLDataJSON)ObjectUtils.DeserializeObject(br);
        }
    }
}
