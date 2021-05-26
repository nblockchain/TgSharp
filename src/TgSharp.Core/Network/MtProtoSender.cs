using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

using TgSharp.TL;
using TgSharp.Core.Exceptions;
using TgSharp.Core.MTProto;
using TgSharp.Core.MTProto.Crypto;
using TgSharp.Core.Network.Exceptions;
using TgSharp.Core.Network.Requests;
using TgSharp.Core.Utils;
using System.Collections.Concurrent;
using Timer = System.Timers.Timer;

namespace TgSharp.Core.Network
{
    internal class MtProtoSender : IDisposable
    {
        private readonly WSTransport transport;
        private readonly ISessionStore sessionStore;
        private readonly Session session;
        private readonly ConcurrentDictionary<long, TLMethod> pendingRequests = new ConcurrentDictionary<long, TLMethod>();
        public readonly List<ulong> needConfirmation = new List<ulong>();

        private readonly Timer heartBeatTimer = new Timer(TimeSpan.FromMinutes(3).TotalMilliseconds);

        internal MtProtoSender(WSTransport transport, ISessionStore sessionStore, Session session)
        {
            this.transport = transport;
            this.sessionStore = sessionStore;
            this.session = session;

            heartBeatTimer.Start();

            this.transport.OnEncryptedMessage += Transport_OnEncryptedMessage;
            heartBeatTimer.Elapsed += SendHeartBeat;
        }

        private int GenerateSequence(bool confirmed)
        {
            lock (session.Lock) {
                try {
                    return confirmed ? session.Sequence++ * 2 + 1 : session.Sequence * 2;
                } finally {
                    sessionStore.Save(session);
                }
            }
        }

        private void SendHeartBeat(object sender, System.Timers.ElapsedEventArgs e)
        {
            var ping = new TLPing
            {
                PingId = Helpers.GenerateRandomLong()
            };

            Request(ping);
        }

        private Tuple<byte[], ulong, int> DecryptMessage(byte[] body)
        {
            byte[] message;
            ulong remoteMessageId;
            int remoteSequence;

            using (var inputStream = new MemoryStream(body))
            using (var inputReader = new BinaryReader(inputStream))
            {
                if (inputReader.BaseStream.Length < 8)
                    throw new InvalidOperationException("Can't decode packet");

                ulong remoteAuthKeyId = inputReader.ReadUInt64(); // TODO: check auth key id
                byte[] msgKey = inputReader.ReadBytes(16); // TODO: check msg_key correctness
                AESKeyData keyData = Helpers.CalcKey(session.AuthKey.Data, msgKey, false);

                byte[] plaintext = AES.DecryptAES(keyData, inputReader.ReadBytes((int)(inputStream.Length - inputStream.Position)));

                using (MemoryStream plaintextStream = new MemoryStream(plaintext))
                using (BinaryReader plaintextReader = new BinaryReader(plaintextStream))
                {
                    var remoteSalt = plaintextReader.ReadUInt64();
                    var remoteSessionId = plaintextReader.ReadUInt64();
                    remoteMessageId = plaintextReader.ReadUInt64();
                    remoteSequence = plaintextReader.ReadInt32();
                    int msgLen = plaintextReader.ReadInt32();
                    message = plaintextReader.ReadBytes(msgLen);
                }
            }
            return new Tuple<byte[], ulong, int>(message, remoteMessageId, remoteSequence);
        }

        private void Transport_OnEncryptedMessage(Message message)
        {
            var result = DecryptMessage(message.Body);

            using (var messageStream = new MemoryStream(result.Item1, false))
            using (var messageReader = new BinaryReader(messageStream))
            {
                HandleMessage(result.Item2, result.Item3, messageReader);
            }
        }

        internal Task<T> Request<T>(TLMethod<T> request, CancellationToken token = default)
        {
            // TODO: refactor
            if (needConfirmation.Any())
            {
                var ackRequest = new AckRequest(needConfirmation);
                using (var memory = new MemoryStream())
                using (var writer = new BinaryWriter(memory))
                {
                    ackRequest.SerializeBody(writer);
                    Send(memory.ToArray());
                    needConfirmation.Clear();
                }
            }

            request.CompletionSource = new TaskCompletionSource<T>();

            using (var memory = new MemoryStream())
            using (var writer = new BinaryWriter(memory))
            {
                request.SerializeBody(writer);
                var msgId = Send(memory.ToArray(), request.ContentRelated);

                if (request is TLPing)
                    //save ping requests by pingId instead of messageId
                    pendingRequests.TryAdd(GetPingId(request), request);
                else
                    pendingRequests.TryAdd(msgId, request);
            }

            sessionStore.Save (session);

            token.Register(() => request.CompletionSource.TrySetCanceled(), useSynchronizationContext: false);

            return request.CompletionSource.Task;
        }

        private void RetryRequest(long msgId)
        {
            if (pendingRequests.TryRemove(msgId, out var request))
            {
                if (needConfirmation.Any())
                {
                    var ackRequest = new AckRequest(needConfirmation);
                    using (var memory = new MemoryStream())
                    using (var writer = new BinaryWriter(memory))
                    {
                        ackRequest.SerializeBody(writer);
                        Send(memory.ToArray());
                        needConfirmation.Clear();
                    }
                }

                using (var memory = new MemoryStream())
                using (var writer = new BinaryWriter(memory))
                {
                    request.SerializeBody(writer);
                    var newMsgId =
                        Send(memory.ToArray(), request.ContentRelated);

                    pendingRequests.TryAdd(newMsgId, request);
                }

                sessionStore.Save(session);
            }
        }

        private long Send(byte[] packet, bool contentRelated = false)
        {
            var messageId = session.GetNewMessageId();

            byte[] msgKey;
            byte[] ciphertext;
            using (MemoryStream plaintextPacket = makeMemory(8 + 8 + 8 + 4 + 4 + packet.Length))
            {
                using (BinaryWriter plaintextWriter = new BinaryWriter(plaintextPacket))
                {
                    plaintextWriter.Write(session.Salt);
                    plaintextWriter.Write(session.Id);
                    plaintextWriter.Write(messageId);
                    plaintextWriter.Write(GenerateSequence(contentRelated));
                    plaintextWriter.Write(packet.Length);
                    plaintextWriter.Write(packet);

                    msgKey = Helpers.CalcMsgKey(plaintextPacket.GetBuffer());
                    ciphertext = AES.EncryptAES(Helpers.CalcKey(session.AuthKey.Data, msgKey, true), plaintextPacket.GetBuffer());
                }
            }

            using (MemoryStream ciphertextPacket = makeMemory(8 + 16 + ciphertext.Length))
            {
                using (BinaryWriter writer = new BinaryWriter(ciphertextPacket))
                {
                    writer.Write(session.AuthKey.Id);
                    writer.Write(msgKey);
                    writer.Write(ciphertext);

                    transport.Send(ciphertextPacket.GetBuffer());
                }
            }


            return messageId;
        }

        private bool HandleMessage(ulong messageId, int sequence, BinaryReader messageReader)
        {
            // TODO: check salt
            // TODO: check sessionid
            // TODO: check seqno

            needConfirmation.Add(messageId);

            uint code = messageReader.ReadUInt32();
            messageReader.BaseStream.Position -= 4;
            switch (code)
            {
                case 0x73f1f8dc: // container
                                 //logger.debug("MSG container");
                    return HandleContainer(messageId, sequence, messageReader);
                case 0x7abe77ec: // ping
                                 //logger.debug("MSG ping");
                    return HandlePing(messageId, sequence, messageReader);
                case 0x347773c5: // pong
                                 //logger.debug("MSG pong");
                    return HandlePong(messageId, sequence, messageReader);
                case 0xae500895: // future_salts
                                 //logger.debug("MSG future_salts");
                    return HandleFutureSalts(messageId, sequence, messageReader);
                case 0x9ec20908: // new_session_created
                                 //logger.debug("MSG new_session_created");
                    return HandleNewSessionCreated(messageId, sequence, messageReader);
                case 0x62d6b459: // msgs_ack
                                 //logger.debug("MSG msds_ack");
                    return HandleMsgsAck(messageId, sequence, messageReader);
                case 0xedab447b: // bad_server_salt
                                 //logger.debug("MSG bad_server_salt");
                    return HandleBadServerSalt(messageId, sequence, messageReader);
                case 0xa7eff811: // bad_msg_notification
                                 //logger.debug("MSG bad_msg_notification");
                    return HandleBadMsgNotification(messageId, sequence, messageReader);
                case 0x276d3ec6: // msg_detailed_info
                                 //logger.debug("MSG msg_detailed_info");
                    return HandleMsgDetailedInfo(messageId, sequence, messageReader);
                case 0xf35c6d01: // rpc_result
                                 //logger.debug("MSG rpc_result");
                    return HandleRpcResult(messageId, sequence, messageReader);
                case 0x3072cfa1: // gzip_packed
                                 //logger.debug("MSG gzip_packed");
                    return HandleGzipPacked(messageId, sequence, messageReader);
                case 0xe317af7e:
                case 0xd3f45784:
                case 0x2b2fbd4e:
                case 0x78d4dec1:
                case 0x725b04c3:
                case 0x74ae4240:
                    return HandleUpdate(messageId, sequence, messageReader);
                default:
                    //logger.debug("unknown message: {0}", code);
                    return false;
            }
        }

        private bool HandleUpdate(ulong messageId, int sequence, BinaryReader messageReader)
        {
            return false;

            /*
			try
			{
				UpdatesEvent(TL.Parse<Updates>(messageReader));
				return true;
			}
			catch (Exception e)
			{
				logger.warning("update processing exception: {0}", e);
				return false;
			}
			*/
        }

        private bool HandleGzipPacked(ulong messageId, int sequence, BinaryReader messageReader)
        {
            _ = messageReader.ReadUInt32();

            byte[] packedData = Serializers.Bytes.Read(messageReader);
            using (var ms = new MemoryStream())
            {
                using (var packedStream = new MemoryStream(packedData, false))
                using (var zipStream = new GZipStream(packedStream, CompressionMode.Decompress))
                {
                    zipStream.CopyTo(ms);
                    ms.Position = 0;
                }
                using (BinaryReader compressedReader = new BinaryReader(ms))
                {
                    HandleMessage(messageId, sequence, compressedReader);
                }
            }

            return true;
        }

        private bool HandleRpcResult(ulong messageId, int sequence, BinaryReader messageReader)
        {
            _ = messageReader.ReadUInt32();
            long requestId = messageReader.ReadInt64();

            uint innerCode = messageReader.ReadUInt32();
            if (innerCode == 0x2144ca19)
            {
                try
                {
                    // rpc_error
                    int errorCode = messageReader.ReadInt32();
                    string errorMessage = Serializers.String.Read(messageReader);

                    if (errorMessage.StartsWith("FLOOD_WAIT_"))
                    {
                        var resultString = Regex.Match(errorMessage, @"\d+").Value;
                        var seconds = int.Parse(resultString);
                        throw new FloodException(TimeSpan.FromSeconds(seconds));
                    }
                    else if (errorMessage.StartsWith("PHONE_MIGRATE_"))
                    {
                        var resultString = Regex.Match(errorMessage, @"\d+").Value;
                        var dcIdx = int.Parse(resultString);
                        throw new PhoneMigrationException(dcIdx);
                    }
                    else if (errorMessage.StartsWith("FILE_MIGRATE_"))
                    {
                        var resultString = Regex.Match(errorMessage, @"\d+").Value;
                        var dcIdx = int.Parse(resultString);
                        throw new FileMigrationException(dcIdx);
                    }
                    else if (errorMessage.StartsWith("USER_MIGRATE_"))
                    {
                        var resultString = Regex.Match(errorMessage, @"\d+").Value;
                        var dcIdx = int.Parse(resultString);
                        throw new UserMigrationException(dcIdx);
                    }
                    else if (errorMessage.StartsWith("NETWORK_MIGRATE_"))
                    {
                        var resultString = Regex.Match(errorMessage, @"\d+").Value;
                        var dcIdx = int.Parse(resultString);
                        throw new NetworkMigrationException(dcIdx);
                    }
                    else if (errorMessage == "PHONE_CODE_INVALID")
                    {
                        throw new InvalidPhoneCodeException("The numeric code used to authenticate does not match the numeric code sent by SMS/Telegram");
                    }
                    else if (errorMessage == "SESSION_PASSWORD_NEEDED")
                    {
                        throw new CloudPasswordNeededException("This Account has Cloud Password !");
                    }
                    else
                    {
                        throw new InvalidOperationException(errorMessage);
                    }
                }
                catch (Exception ex)
                {
                    SetRequestException(requestId, ex);
                }
            }
            else if (innerCode == 0x3072cfa1)
            {
                // gzip_packed
                byte[] packedData = Serializers.Bytes.Read(messageReader);
                using (var ms = new MemoryStream())
                {
                    using (var packedStream = new MemoryStream(packedData, false))
                    using (var zipStream = new GZipStream(packedStream, CompressionMode.Decompress))
                    {
                        zipStream.CopyTo(ms);
                        ms.Position = 0;
                    }
                    using (var compressedReader = new BinaryReader(ms))
                    {
                        ReadRequestResponse(requestId, compressedReader);
                    }
                }
            }
            else
            {
                messageReader.BaseStream.Position -= 4;
                ReadRequestResponse(requestId, messageReader);
            }

            return false;
        }

        private bool HandleMsgDetailedInfo(ulong messageId, int sequence, BinaryReader messageReader)
        {
            return false;
        }

        private bool HandleBadMsgNotification(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            long requestId = messageReader.ReadInt64();
            int requestSequence = messageReader.ReadInt32();
            int errorCode = messageReader.ReadInt32();

            try
            {
                switch (errorCode)
                {
                    case 16:
                        throw new InvalidOperationException("msg_id too low (most likely, client time is wrong; it would be worthwhile to synchronize it using msg_id notifications and re-send the original message with the “correct” msg_id or wrap it in a container with a new msg_id if the original message had waited too long on the client to be transmitted)");
                    case 17:
                        throw new InvalidOperationException("msg_id too high (similar to the previous case, the client time has to be synchronized, and the message re-sent with the correct msg_id)");
                    case 18:
                        throw new InvalidOperationException("incorrect two lower order msg_id bits (the server expects client message msg_id to be divisible by 4)");
                    case 19:
                        throw new InvalidOperationException("container msg_id is the same as msg_id of a previously received message (this must never happen)");
                    case 20:
                        throw new InvalidOperationException("message too old, and it cannot be verified whether the server has received a message with this msg_id or not");
                    case 32:
                        throw new InvalidOperationException("msg_seqno too low (the server has already received a message with a lower msg_id but with either a higher or an equal and odd seqno)");
                    case 33:
                        throw new InvalidOperationException(" msg_seqno too high (similarly, there is a message with a higher msg_id but with either a lower or an equal and odd seqno)");
                    case 34:
                        throw new InvalidOperationException("an even msg_seqno expected (irrelevant message), but odd received");
                    case 35:
                        throw new InvalidOperationException("odd msg_seqno expected (relevant message), but even received");
                    case 48:
                        throw new InvalidOperationException("incorrect server salt (in this case, the bad_server_salt response is received with the correct salt, and the message is to be re-sent with it)");
                    case 64:
                        throw new InvalidOperationException("invalid container");

                        throw new InvalidOperationException($"Unknown error code ({errorCode})");
                }
            }
            catch (InvalidOperationException ex)
            {
                SetRequestException(requestId, ex);
            }

            return true;
        }

        private bool HandleBadServerSalt(ulong messageId, int sequence, BinaryReader messageReader)
        {
            _ = messageReader.ReadUInt32(); //bad_server_salt constructor
            long badMsgId = messageReader.ReadInt64();
            int badMsgSeqNo = messageReader.ReadInt32();
            int errorCode = messageReader.ReadInt32();
            ulong newSalt = messageReader.ReadUInt64();

            session.Salt = newSalt;
            RetryRequest(badMsgId);

            return true;
        }

        private bool HandleMsgsAck(ulong messageId, int sequence, BinaryReader messageReader)
        {
            return false;
        }

        private bool HandleNewSessionCreated(ulong messageId, int sequence, BinaryReader messageReader)
        {
            return false;
        }

        private bool HandleFutureSalts(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            ulong requestId = messageReader.ReadUInt64();

            messageReader.BaseStream.Position -= 12;

            throw new NotImplementedException("Handle future server salts function isn't implemented.");
            /*
			if (!runningRequests.ContainsKey(requestId))
			{
				logger.info("future salts on unknown request");
				return false;
			}
			*/

            //	MTProtoRequest request = runningRequests[requestId];
            //	runningRequests.Remove(requestId);
            //	request.OnResponse(messageReader);

            return true;
        }

        private bool HandlePong(ulong messageId, int sequence, BinaryReader messageReader)
        {
            _ = messageReader.ReadUInt32(); //pong_constructor
            long pingId = messageReader.ReadInt64();
            messageReader.BaseStream.Position -= 12;

            ReadRequestResponse(pingId, messageReader);

            return false;
        }

        private bool HandlePing(ulong messageId, int sequence, BinaryReader messageReader)
        {
            var ping = (TLPing)ObjectUtils.DeserializeObject(messageReader);

            var pong = new TLPong
            {
                MessageId = (long)messageId,
                PingId = ping.PingId
            };

            Send(pong.Serialize(), false);

            return true;
        }

        private bool HandleContainer(ulong messageId, int sequence, BinaryReader messageReader)
        {
            uint code = messageReader.ReadUInt32();
            int size = messageReader.ReadInt32();
            for (int i = 0; i < size; i++)
            {
                ulong innerMessageId = messageReader.ReadUInt64();
                int innerSequence = messageReader.ReadInt32();
                int innerLength = messageReader.ReadInt32();
                long beginPosition = messageReader.BaseStream.Position;
                try
                {
                    if (!HandleMessage(innerMessageId, sequence, messageReader))
                    {
                        messageReader.BaseStream.Position = beginPosition + innerLength;
                    }
                }
                catch (Exception e)
                {
                    //	logger.error("failed to process message in container: {0}", e);
                    messageReader.BaseStream.Position = beginPosition + innerLength;
                }
            }

            return false;
        }

        private long GetPingId(TLMethod pingRequest)
        {
            return ((TLPing)pingRequest).PingId;
        }

        private void SetRequestException(long msgId, Exception ex)
        {
            if (pendingRequests.TryRemove(msgId, out var request))
            {
                request.SetException(ex);
            }
        }

        private void ReadRequestResponse(long msgId, BinaryReader messageReader)
        {
            if (pendingRequests.TryRemove(msgId, out var request))
            {
                request.ReadResponse(messageReader);
            }
        }

        private MemoryStream makeMemory(int len)
        {
            return new MemoryStream(new byte[len], 0, len, true, true);
        }

        public void Dispose()
        {
            transport.Dispose();
            heartBeatTimer.Dispose();
        }
    }
}
