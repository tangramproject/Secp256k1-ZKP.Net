using System;
using System.Collections.Generic;
using System.Text;
using Xunit;

namespace Secp256k1_ZKP.Net.Test
{
    public class Tests
    {
        [Fact]
        public void Commit_Parse_Serialize()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                var commit = pedersen.Commit(5, secp256k1.GetSecretKey());
                var parsed = pedersen.CommitParse(commit);
                var ser = pedersen.CommitSerialize(parsed);

                Assert.Equal(ser, commit);
            }
        }

        [Fact]
        public void Verify_Commit_Sum_Zero_Keys()
        {
            using (var pedersen = new Pedersen())
            {
                byte[] Commit(ulong value)
                {
                    var zeroKey = new byte[32];
                    return pedersen.Commit(value, zeroKey);
                }

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { }, new List<byte[]> { }));

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { Commit(5) }, new List<byte[]> { Commit(5) }));

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { Commit(3), Commit(2) }, new List<byte[]> { Commit(5) }));

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { Commit(2), Commit(4) }, new List<byte[]> { Commit(1), Commit(5) }));
            }
        }

        [Fact]
        public void Verify_Commit_Sum_One_Keys()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                byte[] Commit(ulong value, byte[] blinding)
                {
                    return pedersen.Commit(value, blinding);
                }

                var oneKey = secp256k1.GetSecretKey();

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { Commit(5, oneKey) }, new List<byte[]> { Commit(5, oneKey) }));

                // This will fail.. the values add up to 0. But the keys don't add to 0..
                Assert.False(pedersen.VerifyCommitSum(new List<byte[]> { Commit(3, oneKey), Commit(2, oneKey) }, new List<byte[]> { Commit(5, oneKey) }));


                // To add the keys to 0 we need to sum on both side..
                var twoKey = pedersen.BlindSum(new List<byte[]> { oneKey, oneKey }, new List<byte[]> { });

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { Commit(3, oneKey), Commit(2, oneKey) }, new List<byte[]> { Commit(5, twoKey) }));
            }
        }

        [Fact]
        public void Commit_Sum_Random_Keys()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                byte[] Commit(ulong value, byte[] blinding)
                {
                    return pedersen.Commit(value, blinding);
                }

                var blindPos = secp256k1.GetSecretKey();
                var blindNeg = secp256k1.GetSecretKey();

                var blindSum = pedersen.BlindSum(new List<byte[]> { blindPos }, new List<byte[]> { blindNeg });

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { Commit(101, blindPos) }, new List<byte[]> { Commit(75, blindNeg), Commit(26, blindSum) }));
            }
        }

        [Fact]
        public void Verify_Commit_Sum_Random_Keys_Switch()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                byte[] Commit(ulong value, byte[] blinding)
                {
                    return pedersen.Commit(value, blinding);
                }

                ulong posValue = 101;
                ulong negValue = 75;

                var blindPos = pedersen.BlindSwitch(posValue, secp256k1.GetSecretKey());
                var blindNeg = pedersen.BlindSwitch(negValue, secp256k1.GetSecretKey());

                var blindSum = pedersen.BlindSum(new List<byte[]> { blindPos }, new List<byte[]> { blindNeg });

                var diff = posValue - negValue;

                Assert.True(pedersen.VerifyCommitSum(new List<byte[]> { Commit(posValue, blindPos) }, new List<byte[]> { Commit(negValue, blindNeg), Commit(diff, blindSum) }));
            }
        }

        [Fact]
        public void To_Pubkey()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(5, blinding);
                var pubKey = pedersen.ToPublicKey(commit);

                Assert.NotNull(pubKey);
            }
        }

        [Fact]
        public void Sign_With_PubKey_From_Commitment()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                string ToHex(byte[] data)
                {
                    return BitConverter.ToString(data).Replace("-", string.Empty);
                }

                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(0, blinding);

                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);

                var sig = secp256k1.Sign(msgHash, blinding);

                var pubKey = pedersen.ToPublicKey(commit);

                Assert.True(secp256k1.Verify(sig, msgHash, pubKey));

                var actualPubKey = secp256k1.PublicKeyCreate(blinding);

                Assert.Equal(ToHex(pubKey), ToHex(actualPubKey));
            }
        }

        [Fact]
        public void Commit_Sum()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            {
                string ToHex(byte[] data)
                {
                    return BitConverter.ToString(data).Replace("-", string.Empty);
                }

                var blindA = secp256k1.GetSecretKey();
                var blindB = secp256k1.GetSecretKey();

                var commitA = pedersen.Commit(3, blindA);

                var commitB = pedersen.Commit(2, blindB);

                var blindC = pedersen.BlindSum(new List<byte[]> { blindA, blindB }, new List<byte[]> { });

                var commitC = pedersen.Commit(3 + 2, blindC);

                var commitD = pedersen.CommitSum(new List<byte[]> { commitA, commitB }, new List<byte[]> { });

                Assert.Equal(ToHex(commitC), ToHex(commitD));

                var blindE = pedersen.BlindSum(new List<byte[]> { blindA }, new List<byte[]> { blindB });

                var commitE = pedersen.Commit(3 - 2, blindE);

                var commitF = pedersen.CommitSum(new List<byte[]> { commitA }, new List<byte[]> { commitB });

                Assert.Equal(ToHex(commitE), ToHex(commitF));
            }
        }

    }
}
