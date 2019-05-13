using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using Secp256k1_ZKP.Net;

namespace Examples
{
    class Program
    {
        static void Main(string[] args)
        {

            TestRangeProof();
        }

        static void TestToPublicKey()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                var blinding = secp256k1.GetSecretKey();

                var commit = pedersen.Commit(0, blinding);

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = secp256k1.Sign(msgHash, blinding);

                var pubKey = pedersen.ToPublicKey(commit);

                var verified1 = secp256k1.Verify(sig, msgHash, pubKey);
                var pub = secp256k1.PublicKeyCreate(blinding);
            }
        }

        static void TestRangeProof()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var rangeProof = new RangeProof())
            {
                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(100, blinding);
                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);
                var proof = rangeProof.Proof(0, 100, blinding, commit, msgHash);
                var verified = rangeProof.Verify(commit, proof);
 

                var proofInfo = rangeProof.Info(proof);

                proofInfo = rangeProof.Rewind(commit, proof, blinding);

                var badNonce = secp256k1.GetSecretKey();
                var badInfo = rangeProof.Rewind(commit, proof, badNonce);

                commit = pedersen.Commit(0, blinding);
                proof = rangeProof.Proof(0, 0, blinding, commit, msgHash);
                rangeProof.Verify(commit, proof);
                proofInfo = rangeProof.Rewind(commit, proof, blinding);
            }
        }

        static string ToHex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }

        static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

    }
}
