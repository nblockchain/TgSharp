using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using TgSharp.TL;

namespace TgSharp.TL.Contacts
{
    [TLObject(-2098076769)]
    public class TLRequestGetSaved : TLMethod<TLVector<TLSavedPhoneContact>>
    {
        public override int Constructor
        {
            get
            {
                return -2098076769;
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
            Response = (TLVector<TLSavedPhoneContact>)ObjectUtils.DeserializeVector<TLSavedPhoneContact>(br);
        }
    }
}
