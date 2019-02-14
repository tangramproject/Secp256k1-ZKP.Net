using System;
using System.Text;
using Secp256k1_ZKP.Net;

namespace Examples
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(5, blinding);

                commit = pedersen.CommitParse(commit);

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);
                var sig = secp256k1.Sign(msgHash, blinding);
                var pubKey = pedersen.ToPublicKey(commit);

                // pubKey = secp256k1.PubKeySerialize(pubKey, Flags.SECP256K1_EC_COMPRESSED);

                // Fails.....
                var verified1 = secp256k1.Verify(sig, msgHash, pubKey);


                // Works....
                var pub = secp256k1.PublicKeyCreate(blinding);

                var verified2 = secp256k1.Verify(sig, msgHash, pub);

            }
        }

        static string ToHex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }
    }
}
