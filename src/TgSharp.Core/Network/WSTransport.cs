using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.WebSockets;
using System.Reactive.Concurrency;
using System.Reactive.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TgSharp.Core.MTProto.Crypto;
using Websocket.Client;
using Websocket.Client.Models;

namespace TgSharp.Core.Network
{
    internal class WSTransport
    {
        private WebsocketClient client;
        private const uint protocol = 0xeeeeeeee;
        private readonly RandomNumberGenerator rngSource;
        private readonly string address;
        private readonly int port;
        private byte[] encryptKey, encryptIV, decryptKey, decryptIV;

        private byte[] encryptCount = new byte[16], decryptCount = new byte[16];
        private int encryptNum = 0, decryptNum = 0;

        public Action<Message> OnEncryptedMessage, OnUnencryptedMessage;
        private static readonly object syncGate = new object();


        internal WSTransport(string address, int port)
        {
            Array.Clear(encryptCount, 0, encryptCount.Length);
            Array.Clear(decryptCount, 0, decryptCount.Length);

            rngSource = RandomNumberGenerator.Create();
            this.address = address;
            this.port = port;
        }

        private async Task InitializeClient()
        {
            if (client != null)
                client.Dispose();

            client = new WebsocketClient(new Uri($"ws://{address}:{port}/apiws"));

            client
                .MessageReceived
                .Select(msg => Observable.FromAsync(async () =>
                {
                    await HandleIncomingMessage(msg);
                }))
                .Concat()
                .Subscribe();

            client
                .ReconnectionHappened
                .Select(msg => Observable.FromAsync(async () =>
                {
                    await TryToReconnect(msg);
                }))
                .Concat()
                .Subscribe();

            await client.StartOrFail();
        }

        private async Task TryToReconnect(ReconnectionInfo obj)
        {
            if (client.IsRunning)
                await InitializeConnection();
        }

        private async Task HandleIncomingMessage(ResponseMessage msg)
        {
            byte[] unencryptedData = new byte[msg.Binary.Length];
            AesCtr.Ctr128Encrypt(msg.Binary, decryptKey, ref decryptIV, ref decryptCount, ref decryptNum, unencryptedData);

            var tcpMessage = Message.Decode(unencryptedData);

            var authKeyId = BitConverter.ToInt64(tcpMessage.Body, 0);

            if (authKeyId == 0)
                OnUnencryptedMessage?.Invoke(tcpMessage);
            else
                OnEncryptedMessage?.Invoke(tcpMessage);
        }

        private async Task InitializeConnection()
        {
            byte[] init = new byte[64];

            while (true)
            {
                rngSource.GetNonZeroBytes(init);
                if (init[0] == 0xef)
                    continue;

                uint firstInt = BitConverter.ToUInt32(init, 0);
                if (firstInt == 0x44414548 || firstInt == 0x54534f50 || firstInt == 0x20544547 || firstInt == 0x4954504f || firstInt == 0x02010316 || firstInt == 0xdddddddd || firstInt == 0xeeeeeeee)
                    continue;

                uint secondInt = BitConverter.ToUInt32(init, 4);
                if (secondInt == 0x00000000)
                    continue;

                break;
            }

            Buffer.BlockCopy(BitConverter.GetBytes(protocol), 0, init, 56, 4);

            byte[] initRev = init.Reverse().ToArray();

            encryptKey = new byte[32];
            Buffer.BlockCopy(init, 8, encryptKey, 0, 32);
            decryptKey = new byte[32];
            Buffer.BlockCopy(initRev, 8, decryptKey, 0, 32);

            encryptIV = new byte[16];
            Buffer.BlockCopy(init, 40, encryptIV, 0, 16);
            decryptIV = new byte[16];
            Buffer.BlockCopy(initRev, 40, decryptIV, 0, 16);

            byte[] encryptedInit = new byte[init.Length];
            AesCtr.Ctr128Encrypt(init, encryptKey, ref encryptIV, ref encryptCount, ref encryptNum, encryptedInit);

            byte[] finalInit = new byte[64];
            Buffer.BlockCopy(init, 0, finalInit, 0, 56);
            Buffer.BlockCopy(encryptedInit, 56, finalInit, 56, 8);

            await client.SendInstant(finalInit);
        }

        internal async Task ConnectAsync(int retryCount)
        {
            do
            {
                try
                {
                    await InitializeClient();
                    return;
                }
                catch
                {
                    if (retryCount == 0)
                        throw;
                }
            } while (--retryCount >= 0);
        }

        internal void Send(byte[] packet)
        {
            if (!client.IsRunning)
                throw new InvalidOperationException("Client not connected to server.");

            var tcpMessage = new Message(packet).Encode();

            byte[] encryptedMessage = new byte[tcpMessage.Length];
            AesCtr.Ctr128Encrypt(tcpMessage, encryptKey, ref encryptIV, ref encryptCount, ref encryptNum, encryptedMessage);

            client.Send(encryptedMessage);
        }

        internal void Dispose()
        {
            client.Dispose();
            client = null;
        }

        internal bool IsConnected()
        {
            return client.IsRunning;
        }
    }
}
