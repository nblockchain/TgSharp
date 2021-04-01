using System;

namespace TgSharp.Core
{
    public class DataCenter
    {
        private const string defaultConnectionAddress = "149.154.175.100";//"149.154.167.50";
        private const int defaultConnectionPort = 443;

        [Obsolete ("Do not use, this ctor is public only for serialization")]
        public DataCenter ()
        {
        }

        internal DataCenter (int? dcId, string address = defaultConnectionAddress, int port = defaultConnectionPort)
        {
            DataCenterId = dcId;
            Address = address;
            Port = port;
        }

        public int? DataCenterId { get; set; }
        public string Address { get; set; }
        public int Port { get; set; }
    }
}