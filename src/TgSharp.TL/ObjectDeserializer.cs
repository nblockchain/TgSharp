using System;
using System.IO;

namespace TgSharp.TL
{
    public class ObjectUtils
    {
        public static object DeserializeObject(BinaryReader reader)
        {
            int Constructor = reader.ReadInt32();

            object obj;
            Type t = null;
            try
            {
                t = TLContext.getType(Constructor);
                obj = Activator.CreateInstance(t);
            }
            catch (Exception ex)
            {
                throw new InvalidDataException($"Unknown object constructor ({Constructor}), this should not happen feel free to post an issue on our Github repository.", ex);
            }

            if (t.IsSubclassOf(typeof(TLMethod)))
            {
                ((TLMethod)obj).DeserializeResponse(reader);
                return obj;
            }
            else if (t.IsSubclassOf(typeof(TLObject)))
            {
                ((TLObject)obj).DeserializeBody(reader);
                return obj;
            }
            else throw new NotImplementedException("Weird Type : " + t.Namespace + " | " + t.Name);
        }
        public static void SerializeObject(object obj, BinaryWriter writer)
        {
            ((TLObject)obj).SerializeBody(writer);
        }
        public static TLVector<T> DeserializeVector<T>(BinaryReader reader)
        {
            int constructor = reader.ReadInt32();
            if (constructor != 481674261) throw new InvalidDataException($"Incorrect vector constructor, expected {481674261} received {constructor}");
            TLVector<T> t = new TLVector<T>();
            t.DeserializeBody(reader);
            return t;
        }
    }
}
