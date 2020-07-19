using System;
using static Secp256k1Zkp.Secp256k1Native;
using static Secp256k1Zkp.RangeProofNative;

namespace Secp256k1Zkp
{
    public struct ProofInfoStruct
    {
        public bool success;
        public ulong value;
        public byte[] message;
        public byte[] blindin;
        public uint mlen;
        public ulong min;
        public ulong max;
        public int exp;
        public int mantissa;

        public ProofInfoStruct(bool success, ulong value, byte[] message, byte[] blindin, uint mlen, ulong min, ulong max, int exp, int mantissa)
        {
            this.success = success;
            this.value = value;
            this.message = message;
            this.blindin = blindin;
            this.mlen = mlen;
            this.min = min;
            this.max = max;
            this.exp = exp;
            this.mantissa = mantissa;
        }
    }

    public struct ProofStruct
    {
        public byte[] proof;
        public uint plen;

        public ProofStruct(byte[] proof, uint plen)
        {
            this.proof = proof;
            this.plen = plen;
        }
    }

    public class RangeProof : IDisposable
    {
        public IntPtr Context { get; private set; }

        public RangeProof()
        {
            Context = secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// Produces a range proof for the provided value, using min and max.
        /// </summary>
        /// <returns>The proof.</returns>
        /// <param name="min">Minimum.</param>
        /// <param name="value">Value.</param>
        /// <param name="blind">Blind.</param>
        /// <param name="commit">Commit.</param>
        /// <param name="msg">Message.</param>
        public ProofStruct Proof(ulong min, ulong value, byte[] blind, byte[] commit, byte[] msg)
        {
            if (blind.Length != Constant.BLIND_LENGTH)
                throw new ArgumentException($"{nameof(blind)} must be {Constant.BLIND_LENGTH} bytes");

            if (commit.Length != Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            bool success = false;
            byte[] proof = new byte[Constant.MAX_PROOF_SIZE];
            uint plen = Constant.MAX_PROOF_SIZE;
            byte[] nonce = (byte[])blind.Clone();
            byte[] extraCommit = new byte[33];

            using (var pedersen = new Pedersen())
            {
                commit = pedersen.CommitParse(commit);

                while (success == false)
                {
                    success = secp256k1_rangeproof_sign(
                                Context,
                                proof,
                                ref plen,
                                min,
                                commit,
                                blind,
                                nonce,
                                0,
                                64,
                                value,
                                msg,
                                (uint)msg.Length,
                                extraCommit,
                                0,
                                Constant.GENERATOR_H) == 1;
                }

                return new ProofStruct(proof, plen);
            }
        }

        /// <summary>
        /// General information extracted from a range proof.
        /// </summary>
        /// <returns>The info.</returns>
        /// <param name="struct">Proof.</param>
        public ProofInfoStruct Info(ProofStruct @struct)
        {
            int exp = 0, mantissa = 0;
            ulong min = 0, max = 0;
            byte[] secretKey = new byte[32];

            using (var secp256k1 = new Secp256k1())
                secretKey = secp256k1.CreatePrivateKey();

            var success = secp256k1_rangeproof_info(
                            Context,
                            ref exp,
                            ref mantissa,
                            ref min,
                            ref max,
                            @struct.proof,
                            @struct.plen) == 1;

            return new ProofInfoStruct(
                        success,
                        0,
                        new byte[Constant.PROOF_MSG_SIZE],
                        secretKey,
                        0,
                        min,
                        max,
                        exp,
                        mantissa);
        }

        /// <summary>
        /// Verify a range proof and rewind the proof to recover information
        /// sent by its author.
        /// </summary>
        /// <returns>The rewind.</returns>
        /// <param name="commit">Commit.</param>
        /// <param name="struct">Proof.</param>
        /// <param name="nonce">Nonce.</param>
        public ProofInfoStruct Rewind(byte[] commit, ProofStruct @struct, byte[] nonce)
        {
            if (commit.Length < Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            if (nonce.Length < Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(nonce)} must be {Constant.SECRET_KEY_SIZE} bytes");

            ulong value = 0, min = 0, max = 0;
            byte[] blindOut = new byte[32];
            byte[] message = new byte[Constant.PROOF_MSG_SIZE];
            uint mlen = Constant.PROOF_MSG_SIZE;
            byte[] extraCommit = new byte[33];

            using (var pedersen = new Pedersen())
            {
                commit = pedersen.CommitParse(commit);

                var success = secp256k1_rangeproof_rewind(
                                Context,
                                blindOut,
                                ref value,
                                message,
                                ref mlen,
                                nonce,
                                ref min,
                                ref max,
                                commit,
                                @struct.proof,
                                @struct.plen,
                                extraCommit,
                                0,
                                Constant.GENERATOR_H
                                ) == 1;

                return new ProofInfoStruct(
                            success,
                            value,
                            message,
                            blindOut,
                            mlen,
                            min,
                            max,
                            0,
                            0);
            }
        }

        /// <summary>
        /// Verify a proof that a committed value is within a range.
        /// </summary>
        /// <returns>The verify.</returns>
        /// <param name="commit">Commit.</param>
        /// <param name="struct">Proof.</param>
        public bool Verify(byte[] commit, ProofStruct @struct)
        {
            if (commit.Length < Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            bool success;
            ulong min = 0, max = 0;
            byte[] extraCommit = new byte[33];

            using (var pedersen = new Pedersen())
            {
                commit = pedersen.CommitParse(commit);

                success = secp256k1_rangeproof_verify(
                    Context,
                    ref min,
                    ref max,
                    commit,
                    @struct.proof,
                    @struct.plen,
                    extraCommit,
                    0,
                    Constant.GENERATOR_H) == 1;
            }

            return success;
        }

        public void Dispose()
        {
            if (Context != IntPtr.Zero)
            {
                secp256k1_context_destroy(Context);
                Context = IntPtr.Zero;
            }
        }
    }
}
