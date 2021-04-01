using System;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace TgSharp.Core
{
    public class JsonFileSessionStore : ISessionStore
    {
        private readonly DirectoryInfo basePath;
        private readonly JsonSerializerOptions jsonSerializerSettings;

        internal static JsonFileSessionStore DefaultSessionStore()
        {
            return new JsonFileSessionStore(null, new JsonSerializerOptions()
            {
                WriteIndented = true
            });
        }

        public JsonFileSessionStore(DirectoryInfo basePath = null, JsonSerializerOptions jsonSerializerSettings = null)
        {
            if (basePath != null && !basePath.Exists)
            {
                throw new ArgumentException("basePath doesn't exist", nameof(basePath));
            }

            this.basePath = basePath;
            this.jsonSerializerSettings = jsonSerializerSettings;
        }

        public void Save(Session session)
        {
            var json = JsonSerializer.Serialize(session);
            File.WriteAllText(GetSessionPath(session.SessionUserId), json);
        }

        public Session Load(string sessionUserId)
        {
            string sessionPath = GetSessionPath(sessionUserId);

            if (File.Exists(sessionPath))
            {
                return JsonSerializer.Deserialize<Session>(File.ReadAllText(sessionPath), jsonSerializerSettings);
            }

            return null;
        }

        private string GetSessionPath(string sessionUserId)
        {
            return Path.Combine(basePath?.FullName ?? string.Empty, sessionUserId + ".json");
        }
    }
}
