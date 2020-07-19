using System.Collections.Generic;
using System.Text;
using Secp256k1Zkp;

namespace Examples
{
    class Program
    {
        public const int Tan = 1;
        public const int MicroTan = 100;
        public const int NanoTan = 1000_000_000;
        public const long AttoTan = 1000_000_000_000_000_000;

        static void Main(string[] args)
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                // Correct valu
                int minValue = 1000;
                ulong value = 1000;
                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                var success = bulletProof.Verify(commit, @struct.proof, null);

            }
        }

        static void TestToPublicKey()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                var blinding = secp256k1.GetSecretKey();
                var commitPos = pedersen.Commit(0, blinding);
                var commitNeg = pedersen.Commit(0, blinding);

                var blindSum = pedersen.BlindSum(new List<byte[]> { blinding, blinding }, new List<byte[]> { });

                var commitSum = pedersen.CommitSum(new List<byte[]> { commitPos }, new List<byte[]> { commitNeg });

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = secp256k1.Sign(msgHash, blinding);

                var pubKey = pedersen.ToPublicKey(commitSum);

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

        static void TestRangeProofOnBlock()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var rangeProof = new RangeProof())
            {
                var blinding = secp256k1.GetSecretKey();

                ulong posValue = NaT(3434545);
                ulong negValue = NaT(1.123456789123456789);

                var diff = posValue - negValue;

                var blindPos = pedersen.BlindSwitch(posValue, blinding);
                var blindNeg = pedersen.BlindSwitch(negValue, blinding);

                var blindSum = pedersen.BlindSum(new List<byte[]> { blindPos }, new List<byte[]> { blindNeg });

                var commitPos = pedersen.Commit(posValue, blindPos);
                var commitNeg = pedersen.Commit(negValue, blindNeg);

                var commitSum = pedersen.CommitSum(new List<byte[]> { commitPos }, new List<byte[]> { commitNeg });
                var isVerified = pedersen.VerifyCommitSum(new List<byte[]> { commitPos }, new List<byte[]> { commitNeg, commitSum });

                var commitChange = pedersen.Commit(diff, blinding);

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var proofStruct = rangeProof.Proof(0, diff, blindSum, commitSum, msgHash);

                var verified = rangeProof.Verify(commitSum, proofStruct);
            }
        }

        static ulong NaT(double value)
        {
            return (ulong)(value * NanoTan);
        }
    }
}
