﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using static Secp256k1Zkp.PedersenNative;

namespace Secp256k1Zkp
{
    public class Pedersen : IDisposable
    {
        public IntPtr Context { get; private set; }

        public Pedersen()
        {
            Context = secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// Commit the specified value and blind.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="blind"></param>
        /// <returns></returns>
        public byte[] BlinCommit(byte[] value, byte[] blind)
        {
            if (blind.Length != Constant.BLIND_LENGTH)
                throw new ArgumentException($"{nameof(blind)} must be {Constant.BLIND_LENGTH} bytes");

            //if (value.Length < Constant.BLIND_LENGTH)
            //    throw new ArgumentException($"{nameof(value)} must be {Constant.BLIND_LENGTH} bytes");

            var commit = new byte[Constant.PEDERSEN_COMMITMENT_SIZE_INTERNAL];
            return secp256k1_pedersen_blind_commit(Context, commit, blind, value, Constant.GENERATOR_H, Constant.GENERATOR_G) == 1
                ? CommitSerialize(commit)
                : null;
        }

        /// <summary>
        /// Commit the specified value and blind.
        /// </summary>
        /// <returns>The commit.</returns>
        /// <param name="value">Value.</param>
        /// <param name="blind">Blind.</param>
        public byte[] Commit(ulong value, byte[] blind)
        {
            if (blind.Length != Constant.BLIND_LENGTH)
                throw new ArgumentException($"{nameof(blind)} must be {Constant.BLIND_LENGTH} bytes");

            var commit = new byte[Constant.PEDERSEN_COMMITMENT_SIZE_INTERNAL];
            return secp256k1_pedersen_commit(Context, commit, blind, value, Constant.GENERATOR_H, Constant.GENERATOR_G) == 1
                ? CommitSerialize(commit)
                : null;
        }

        /// <summary>
        /// Commits the parse.
        /// </summary>
        /// <returns>The parse.</returns>
        /// <param name="input">Input.</param>
        public byte[] CommitParse(byte[] input)
        {
            if (input.Length != Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(input)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            var output = new byte[Constant.PEDERSEN_COMMITMENT_SIZE_INTERNAL];
            return secp256k1_pedersen_commitment_parse(Context, output, input) == 1 ? output : null;
        }

        /// <summary>
        /// Commits the serialize.
        /// </summary>
        /// <returns>The serialize.</returns>
        /// <param name="commit">Commit.</param>
        public byte[] CommitSerialize(byte[] commit)
        {
            if (commit.Length != Constant.PEDERSEN_COMMITMENT_SIZE_INTERNAL)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE_INTERNAL} bytes");

            var output = new byte[Constant.PEDERSEN_COMMITMENT_SIZE];
            return secp256k1_pedersen_commitment_serialize(Context, output, commit) == 1 ? output : null;
        }

        /// <summary>
        /// Blinds the sum.
        /// </summary>
        /// <returns>The sum.</returns>
        /// <param name="positive">Positive.</param>
        /// <param name="negative">Negative.</param>
        public byte[] BlindSum(IEnumerable<byte[]> positives, IEnumerable<byte[]> negatives)
        {
            if (positives == null)
                throw new ArgumentNullException("Positives cannot be null.");

            if (negatives == null)
                throw new ArgumentNullException("Negatives cannot be null.");

            var blindOut = new byte[Constant.SECRET_KEY_SIZE];
            var all = new List<byte[]>(positives);

            all.AddRange(negatives);

            var ptrs = new IntPtr[all.Count()];

            for (var i = 0; i < all.Count(); i++)
            {
                var ptr = Marshal.AllocHGlobal(all[i].Length);
                Marshal.Copy(all[i], 0, ptr, all[i].Length);
                ptrs[i] = ptr;
            }

            return secp256k1_pedersen_blind_sum(Context, blindOut, ptrs, (uint)all.Count(), (uint)positives.Count()) == 1
                ? blindOut
                : null;
        }

        /// <summary>
        /// Blinds the switch.
        /// </summary>
        /// <returns>The switch.</returns>
        /// <param name="value">Value.</param>
        /// <param name="blind">Blind.</param>
        public byte[] BlindSwitch(ulong value, byte[] blind)
        {
            if (blind.Length != Constant.BLIND_LENGTH)
                throw new ArgumentException($"{nameof(blind)} must be {Constant.BLIND_LENGTH} bytes");

            var blindSwitch = new byte[Constant.SECRET_KEY_SIZE];

            return secp256k1_blind_switch(Context, blindSwitch, blind, value, Constant.GENERATOR_H, Constant.GENERATOR_G, Constant.GENERATOR_PUB_J_RAW) == 1
                ? blindSwitch
                : null;
        }

        /// <summary>
        /// Verifies the commit sum.
        /// </summary>
        /// <returns><c>true</c>, if commit sum was verifyed, <c>false</c> otherwise.</returns>
        /// <param name="positives">Positives.</param>
        /// <param name="negatives">Negatives.</param>
        public bool VerifyCommitSum(IEnumerable<byte[]> positives, IEnumerable<byte[]> negatives)
        {
            if (positives == null)
                throw new ArgumentNullException("Positives cannot be null.");

            if (negatives == null)
                throw new ArgumentNullException("Negatives cannot be null.");

            var pos = new IntPtr[positives.Count()];
            var neg = new IntPtr[negatives.Count()];
            var i = 0;

            // TODO commenting CommitParse. Just make sure the commeit is 33 bytes serialized..
            positives.ToList().ForEach(p =>
            {
                // p = CommitParse(p);
                var ptr = Marshal.AllocHGlobal(p.Length);
                Marshal.Copy(p, 0, ptr, p.Length);
                pos[i] = ptr;
                i++;
            });
            i = 0;
            negatives.ToList().ForEach(n =>
            {
                // n = CommitParse(n);
                var ptr = Marshal.AllocHGlobal(n.Length);
                Marshal.Copy(n, 0, ptr, n.Length);
                neg[i] = ptr;
                i++;
            });

            return secp256k1_pedersen_verify_tally(Context, pos, (uint)pos.Length, neg, (uint)neg.Length) == 1;
        }

        /// <summary>
        /// Commits the sum.
        /// </summary>
        /// <returns>The sum.</returns>
        /// <param name="positives">Positives.</param>
        /// <param name="negatives">Negatives.</param>
        public byte[] CommitSum(IEnumerable<byte[]> positives, IEnumerable<byte[]> negatives)
        {
            if (positives == null)
                throw new ArgumentNullException("Positives cannot be null.");

            if (negatives == null)
                throw new ArgumentNullException("Negatives cannot be null.");

            var commitOut = new byte[Constant.PEDERSEN_COMMITMENT_SIZE_INTERNAL];
            var pos = new IntPtr[positives.Count()];
            var neg = new IntPtr[negatives.Count()];
            var i = 0;

            positives.ToList().ForEach(p =>
            {
                p = CommitParse(p);
                IntPtr ptr = Marshal.AllocHGlobal(p.Length);
                Marshal.Copy(p, 0, ptr, p.Length);
                pos[i] = ptr;
                i++;
            });
            i = 0;
            negatives.ToList().ForEach(n =>
            {
                n = CommitParse(n);
                IntPtr ptr = Marshal.AllocHGlobal(n.Length);
                Marshal.Copy(n, 0, ptr, n.Length);
                neg[i] = ptr;
                i++;
            });

            return secp256k1_pedersen_commit_sum(Context, commitOut, pos, (uint)pos.Length, neg, (uint)neg.Length) == 1
                ? CommitSerialize(commitOut)
                : null;
        }

        /// <summary>
        /// Converts a commitment to a public key.
        /// </summary>
        /// <returns>The public key.</returns>
        /// <param name="commit">Commit.</param>
        public byte[] ToPublicKey(byte[] commit)
        {
            if (commit.Length != Constant.PEDERSEN_COMMITMENT_SIZE)
                throw new ArgumentException($"{nameof(commit)} must be {Constant.PEDERSEN_COMMITMENT_SIZE} bytes");

            var pubOut = new byte[Constant.PUBLIC_KEY_SIZE];
            return secp256k1_pedersen_commitment_to_pubkey(Context, pubOut, commit) == 1 ? pubOut : null;
        }

        /// <summary>
        /// 
        /// </summary>
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
