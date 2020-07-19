using System;
using System.Collections.Generic;
using System.Text;
using Secp256k1ZKP;
using Xunit;

namespace Test
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

        [Fact]
        public void Range_Proof()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var rangeProof = new RangeProof())
            {
                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(9, blinding);
                var msg = "Message for signing";
                var msgBytes = Encoding.UTF8.GetBytes(msg);
                var msgHash = System.Security.Cryptography.SHA256.Create().ComputeHash(msgBytes);
                var proof = rangeProof.Proof(0, 9, blinding, commit, msgHash);
                var verified = rangeProof.Verify(commit, proof);
                Assert.True(verified);

                var proofInfo = rangeProof.Info(proof);
                Assert.True(proofInfo.success);
                Assert.Equal(0, (long)proofInfo.min);
                Assert.Equal(0, (long)proofInfo.value);

                proofInfo = rangeProof.Rewind(commit, proof, blinding);
                Assert.True(proofInfo.success);
                Assert.Equal(0, (long)proofInfo.min);
                Assert.Equal(9, (long)proofInfo.value);

                var badNonce = secp256k1.GetSecretKey();
                var badInfo = rangeProof.Rewind(commit, proof, badNonce);
                Assert.False(badInfo.success);
                Assert.Equal(0, (long)badInfo.value);

                commit = pedersen.Commit(0, blinding);
                proof = rangeProof.Proof(0, 0, blinding, commit, msgHash);
                rangeProof.Verify(commit, proof);
                proofInfo = rangeProof.Rewind(commit, proof, blinding);
                Assert.True(proofInfo.success);
                Assert.Equal(0, (long)proofInfo.min);
                Assert.Equal(0, (long)proofInfo.value);
            }
        }

        [Fact]
        public void Bullet_Proof()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                // Correct value
                ulong value = 300;
                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                var success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.True(success);

                // Wrong value
                value = 1222344;
                var commitWrong = pedersen.Commit(122111, blinding);
                @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.False(success);

                // Wrong binding
                value = 122322;
                commit = pedersen.Commit(value, blinding);
                blinding = secp256k1.GetSecretKey();
                @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.False(success);
            }
        }

        [Fact]
        public void Bullet_Proof_Minimum_Amount()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                int minValue = 1000;
                ulong value = 300;

                // Correct value and minimum value
                var blinding = secp256k1.GetSecretKey();
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null);
                var success = bulletProof.Verify(commit, @struct.proof, null);

                Assert.True(success);

                // Wrong value < 1000 and minimum value.
                var commitWrong = pedersen.Commit(value, blinding);
                @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), null, null, minValue);
                success = bulletProof.Verify(commit, @struct.proof, null, minValue);

                Assert.False(success);
            }
        }

        [Fact]
        public void Bullet_Proof_Extra_Commit()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                var extraCommit = new byte[32];
                var blinding = secp256k1.GetSecretKey();
                ulong value = 100033;
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), extraCommit, null);
                var success = bulletProof.Verify(commit, @struct.proof, extraCommit);

                Assert.True(success);
            }
        }

        [Fact]
        public void Bullet_Proof_Extra_Commit_Wrong()
        {
            using (var secp256k1 = new Secp256k1())
            using (var pedersen = new Pedersen())
            using (var bulletProof = new BulletProof())
            {
                // Correct extra commit
                var extraCommit = new byte[32];
                var blinding = secp256k1.GetSecretKey();
                ulong value = 100033;
                var commit = pedersen.Commit(value, blinding);
                var @struct = bulletProof.ProofSingle(value, blinding, (byte[])blinding.Clone(), (byte[])blinding.Clone(), extraCommit, null);
                var success = bulletProof.Verify(commit, @struct.proof, extraCommit);

                Assert.True(success);


                //Wrong extra commit
                var extraCommitWrong = new byte[32];
                extraCommitWrong[0] = 1;
                success = bulletProof.Verify(commit, @struct.proof, extraCommitWrong);

                Assert.False(success);
            }
        }

    }
}
