using System;
using System.Threading;
using System.Threading.Tasks;
using TgSharp.Core.Network;

namespace TgSharp.Core.Auth
{
    internal class Authenticator
    {
        private readonly MtProtoPlainSender sender;
        private TaskCompletionSource<Step3_Response> completionSource;
        internal Authenticator(WSTransport transport)
        {
            sender = new MtProtoPlainSender(transport);
            completionSource = new TaskCompletionSource<Step3_Response>();
        }

        internal Task<Step3_Response> DoAuthentication()
        {
            var step1 = new Step1_PQRequest();

            sender.OnResponseReceived = (step1Message) => Sender_OnStep1ResponseReceived(step1, step1Message);
            sender.Send(step1.ToBytes());

            return completionSource.Task;
        }

        private void Sender_OnStep1ResponseReceived(Step1_PQRequest step1, byte[] step1Message)
        {
            var step1Response = step1.FromBytes(step1Message);

            var step2 = new Step2_DHExchange();
            sender.OnResponseReceived = (step2message) => Sender_OnStep2ResponseReceived(step2, step2message);
            sender.Send(step2.ToBytes(
                    step1Response.Nonce,
                    step1Response.ServerNonce,
                    step1Response.Fingerprints,
                    step1Response.Pq));
        }

        private void Sender_OnStep2ResponseReceived(Step2_DHExchange step2, byte[] step2message)
        {
            var step2Response = step2.FromBytes(step2message);


            var step3 = new Step3_CompleteDHExchange();
            sender.OnResponseReceived = (step3Message) => Sender_OnStep3ResponseReceived(step3, step3Message);
            sender.Send(step3.ToBytes(
                    step2Response.Nonce,
                    step2Response.ServerNonce,
                    step2Response.NewNonce,
                    step2Response.EncryptedAnswer));
        }

        private void Sender_OnStep3ResponseReceived(Step3_CompleteDHExchange step3, byte[] response)
        {
            completionSource.SetResult(step3.FromBytes(response));
        }
    }
}