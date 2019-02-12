using System;
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

                var pubKey = pedersen.ToPublicKey(commit);

                var p = secp256k1.PubKeySerialize(pubKey, Flags.SECP256K1_EC_COMPRESSED);

                var msg = new byte[] {
                    0x39, 0x41, 0x14, 0x6C, 0x6F, 0x4C, 0x41, 0x14, 0x36, 0x3D, 0x6E, 0x43, 0x48, 0x3D, 0x6D, 0x15,
                    0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15, 0x15 };

                var sig = secp256k1.Sign(msg, blinding);

                var verified = secp256k1.Verify(sig, msg, p);

            }
        }

        static string ToHex(byte[] data)
        {
            return BitConverter.ToString(data).Replace("-", string.Empty);
        }
    }
}
