using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace TgSharp.TL
{
    public abstract class TLMethod : TLObject {
        /*
         * Content-related Message
         *    A message requiring an explicit acknowledgment. These include all the user and many service messages, virtually all with the exception of containers and acknowledgments. 
         */
        public virtual bool ContentRelated { get; } = true;
        public abstract void ReadResponse(BinaryReader reader);
        public abstract void SetException(Exception ex);
    }

    public abstract class TLMethod<T> : TLMethod
    {
        protected T Response { get; set; }
        public TaskCompletionSource<T> CompletionSource { get; set; }

        protected abstract void DeserializeResponse(BinaryReader stream);

        public override void ReadResponse(BinaryReader reader)
        {
            DeserializeResponse(reader);
            CompletionSource.SetResult(Response);
        }

        public override void SetException(Exception ex) => CompletionSource.SetException(ex);
    }
}
