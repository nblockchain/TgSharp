using System;
using System.IO;

using TgSharp.TL;
using TgSharp.Core.MTProto;
using TgSharp.Core.MTProto.Crypto;
using System.Security.Cryptography;

namespace TgSharp.Core
{
    public interface ISessionStore
    {
        void Save(Session session);
        Session Load(string sessionUserId);
    }

    public class FakeSessionStore : ISessionStore
    {
        public void Save(Session session)
        {

        }

        public Session Load(string sessionUserId)
        {
            return null;
        }
    }

    internal static class SessionFactory
    {
        internal static Session TryLoadOrCreateNew (ISessionStore store, string sessionUserId)
        {
            var session = store.Load (sessionUserId);
            if (null == session) {
                var defaultDataCenter = new DataCenter ();
                session = new Session {
                    Id = GenerateRandomUlong (),
                    SessionUserId = sessionUserId,
                    DataCenter = defaultDataCenter,
                };
            }
            session.Sequence = 0;
            byte[] randomSessionId = new byte[8];
            RandomNumberGenerator.Create().GetNonZeroBytes(randomSessionId);
            session.Id = BitConverter.ToUInt64(randomSessionId, 0);
            return session;
        }

        private static ulong GenerateRandomUlong ()
        {
            var random = new Random ();
            ulong rand = (((ulong)random.Next ()) << 32) | ((ulong)random.Next ());
            return rand;
        }
    }

    public class Session
    {
        internal object Lock = new object ();

        public int Sequence { get; set; }
        public string SessionUserId { get; set; }
        internal DataCenter DataCenter { get; set; }
        public AuthKey AuthKey { get; set; }
        public ulong Id { get; set; }
        public ulong Salt { get; set; }
        public int TimeOffset { get; set; }
        public long LastMessageId { get; set; }
        public int SessionExpires { get; set; }
        public TLUser TLUser { get; set; }
        private Random random;

        public Session()
        {
            random = new Random();
        }

        public long GetNewMessageId()
        {
            long time = Convert.ToInt64((DateTime.UtcNow - new DateTime(1970, 1, 1)).TotalMilliseconds);
            long newMessageId = ((time / 1000 + TimeOffset) << 32) |
                                ((time % 1000) << 22) |
                                (random.Next(524288) << 2); // 2^19
                                                            // [ unix timestamp : 32 bit] [ milliseconds : 10 bit ] [ buffer space : 1 bit ] [ random : 19 bit ] [ msg_id type : 2 bit ] = [ msg_id : 64 bit ]

            if (LastMessageId >= newMessageId)
            {
                newMessageId = LastMessageId + 4;
            }

            LastMessageId = newMessageId;
            return newMessageId;
        }
    }
}
