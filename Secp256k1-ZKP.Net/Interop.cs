using System;
using System.Runtime.InteropServices;
using System.Security;

namespace Secp256k1_ZKP.Net
{

    [SuppressUnmanagedCodeSecurity]
    internal static class Secp256k1Native
    {
#if __IOS__ || (UNITY_IOS && !UNITY_EDITOR)
            private const string nativeLibrary = "__Internal";
#else
        private const string nativeLibrary = "libsecp256k1";
#endif

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr secp256k1_context_create(uint flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void secp256k1_context_destroy(IntPtr ctx);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_ec_seckey_verify(IntPtr ctx, byte[] seed32);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_ecdsa_verify(IntPtr ctx, byte[] sig, byte[] msg32, byte[] pubkey);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_ecdsa_sign(IntPtr ctx, byte[] sig, byte[] msg32, byte[] seckey, IntPtr noncefp, IntPtr ndata);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_ec_pubkey_serialize(IntPtr ctx, byte[] output, ref uint outputlen, byte[] pubkey, uint flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_ec_pubkey_create(IntPtr ctx, byte[] pubKeyOut, byte[] privKeyIn);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr secp256k1_scratch_space_create(IntPtr ctx, uint max_size);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_scratch_space_destroy(IntPtr scratch);
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class PedersenNative
    {
#if __IOS__ || (UNITY_IOS && !UNITY_EDITOR)
            private const string nativeLibrary = "__Internal";
#else
        private const string nativeLibrary = "libsecp256k1";
#endif

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr secp256k1_context_create(uint flags);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void secp256k1_context_destroy(IntPtr ctx);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_pedersen_blind_sum(IntPtr ctx, byte[] blind_out, IntPtr[] blinds, uint n, uint npositive);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_pedersen_commit(IntPtr ctx, byte[] commit, byte[] blind, ulong value, byte[] value_gen, byte[] blind_gen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_pedersen_commitment_serialize(IntPtr ctx, byte[] output, byte[] commit);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_pedersen_commitment_parse(IntPtr ctx, byte[] commit, byte[] input);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_pedersen_commit_sum(IntPtr ctx, byte[] commit_out, IntPtr[] commits, uint pcnt, IntPtr[] ncommits, uint ncnt);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_pedersen_verify_tally(IntPtr ctx, IntPtr[] pos, uint n_pos, IntPtr[] neg, uint n_neg);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_blind_switch(IntPtr ctx, byte[] blind_switch, byte[] blind, ulong value, byte[] value_gen, byte[] blind_gen, byte[] switch_pubkey);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_pedersen_commitment_to_pubkey(IntPtr ctx, byte[] pubkey, byte[] commit);
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class RangeProofNative
    {
#if __IOS__ || (UNITY_IOS && !UNITY_EDITOR)
            private const string nativeLibrary = "__Internal";
#else
        private const string nativeLibrary = "libsecp256k1";
#endif

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_rangeproof_info(IntPtr ctx, ref int exp, ref int mantissa, ref ulong min_value, ref ulong max_value, byte[] proof, uint plen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_rangeproof_rewind(IntPtr ctx, byte[] blind_out, ref ulong value_out, byte[] message_out, ref uint outlen, byte[] nonce, ref ulong min_value,
            ref ulong max_value, byte[] commit, byte[] proof, uint plen, byte[] extra_commit, uint extra_commit_len, byte[] gen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_rangeproof_verify(IntPtr ctx, ref ulong min_value, ref ulong max_value, byte[] commit, byte[] proof, uint plen, byte[] extra_commit, uint extra_commit_len, byte[] gen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_rangeproof_sign(IntPtr ctx, byte[] proof, ref uint plen, ulong min_value, byte[] commit, byte[] blind, byte[] nonce, int exp, int min_bits,
            ulong value, byte[] message, uint msg_len, byte[] extra_commit, uint extra_commit_len, byte[] gen);

    }

    [SuppressUnmanagedCodeSecurity]
    internal static class BulletProofNative
    {
#if __IOS__ || (UNITY_IOS && !UNITY_EDITOR)
            private const string nativeLibrary = "__Internal";
#else
        private const string nativeLibrary = "libsecp256k1";
#endif

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr secp256k1_bulletproof_generators_create(IntPtr ctx, byte[] blinding_gen, int n);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_bulletproof_rangeproof_prove(IntPtr ctx, IntPtr scratch, IntPtr gens, byte[] proof, ref int plen, byte[] tau_x, byte[] t_one, byte[] t_two, IntPtr[] value, IntPtr[] min_value,
            IntPtr[] blind, byte[] commits, int n_commits, byte[] value_gen, int nbits, byte[] nonce, byte[] private_nonce, byte[] extra_commit, int extra_commit_len, byte[] message);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_bulletproof_rangeproof_verify(IntPtr ctx, IntPtr scratch, IntPtr gens, byte[] proof, int plen, IntPtr[] min_value, byte[] commit, int n_commits, int nbits, byte[] value_gen,
            byte[] extra_commit, int extra_commit_len);
    }

    [SuppressUnmanagedCodeSecurity]
    internal static class SchnorrSigNative
    {
#if __IOS__ || (UNITY_IOS && !UNITY_EDITOR)
            private const string nativeLibrary = "__Internal";
#else
        private const string nativeLibrary = "libsecp256k1";

        /// <summary>
        /// Serialize a Schnorr signature.
        /// </summary>
        /// <param name="ctx">A secp256k1 context object.</param>
        /// <param name="out64">Pointer to a 64-byte array to store the serialized signature.</param>
        /// <param name="sig">Pointer to the signature</param>
        /// <returns>1</returns>
        /// <see cref="secp256k1_schnorrsig_parse(IntPtr, byte[], byte[])"/>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_schnorrsig_serialize(IntPtr ctx, byte[] out64, byte[] sig);

        /// <summary>
        /// Parse a Schnorr signature.
        /// </summary>
        /// <param name="ctx">A secp256k1 context object.</param>
        /// <param name="sig">Pointer to a signature object.</param>
        /// <param name="in64">Pointer to the 64-byte signature to be parsed.</param>
        /// <returns>1 when the signature could be parsed, 0 otherwise.</returns>
        /// <remarks>The signature is serialized in the form R||s, where R is a 32-byte public
        /// key(x-coordinate only; the y-coordinate is considered to be the unique
        /// y-coordinate satisfying the curve equation that is a quadratic residue)
        /// and s is a 32-byte big-endian scalar.
        ///
        /// After the call, sig will always be initialized.If parsing failed or the
        /// encoded numbers are out of range, signature validation with it is
        /// guaranteed to fail for every message and public key.
        /// </remarks>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_schnorrsig_parse(IntPtr ctx, byte[] sig, byte[] in64);

        /// <summary>
        /// Create a Schnorr signature.
        /// </summary>
        /// <param name="ctx">Pointer to a context object, initialized for signing (cannot be NULL)</param>
        /// <param name="sig">Pointer to the returned signature (cannot be NULL)</param>
        /// <param name="nonce_is_negated">A pointer to an integer indicates if signing algorithm negated the nonce (can be NULL)</param>
        /// <param name="msg32">The 32-byte message hash being signed (cannot be NULL)</param>
        /// <param name="seckey">Pointer to a 32-byte secret key (cannot be NULL)</param>
        /// <param name="noncefp">Pointer to a nonce generation function. If NULL, secp256k1_nonce_function_bipschnorr is used.</param>
        /// <param name="ndata">Pointer to arbitrary data used by the nonce generation function (can be NULL)</param>
        /// <returns>1 on success, 0 on failure</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_schnorrsig_sign(IntPtr ctx, byte[] sig, ref int nonce_is_negated, byte[] msg32, byte[] seckey, IntPtr noncefp, IntPtr ndata);

        /// <summary>
        /// Verify a Schnorr signature.
        /// </summary>
        /// <param name="ctx">A secp256k1 context object, initialized for verification.</param>
        /// <param name="sig">The signature being verified (cannot be NULL)</param>
        /// <param name="msg32">The 32-byte message hash being verified (cannot be NULL)</param>
        /// <param name="pubkey">Pointer to a public key to verify with (cannot be NULL)</param>
        /// <returns>1 correct signature, 0 incorrect or unparseable signature.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_schnorrsig_verify(IntPtr ctx, byte[] sig, byte[] msg32, byte[] pubkey);

        /// <summary>
        /// Verifies a set of Schnorr signatures.
        /// </summary>
        /// <param name="ctx">A secp256k1 context object, initialized for verification.</param>
        /// <param name="scratch">Scratch space used for the multiexponentiation.</param>
        /// <param name="sig">Array of signatures, or NULL if there are no signatures.</param>
        /// <param name="msg32">Array of messages, or NULL if there are no signatures.</param>
        /// <param name="pk">Array of public keys, or NULL if there are no signatures</param>
        /// <param name="n_sigs">Number of signatures in above arrays. Must be smaller than
        /// 2^31 and smaller than half the maximum size_t value. Must be 0
        /// if above arrays are NULL</param>
        /// <returns>1 if all succeeded, 0 otherwise. In particular, returns 1 if n_sigs is 0.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_schnorrsig_verify_batch(IntPtr ctx, IntPtr scratch, IntPtr[] sig, IntPtr[] msg32, IntPtr[] pk, uint n_sigs);

#endif

    }
    [Flags]
    public enum Flags : uint
    {
        /** All flags' lower 8 bits indicate what they're for. Do not use directly. */
        SECP256K1_FLAGS_TYPE_MASK = ((1 << 8) - 1),
        SECP256K1_FLAGS_TYPE_CONTEXT = (1 << 0),
        SECP256K1_FLAGS_TYPE_COMPRESSION = (1 << 1),

        /** The higher bits contain the actual data. Do not use directly. */
        SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = (1 << 8),
        SECP256K1_FLAGS_BIT_CONTEXT_SIGN = (1 << 9),
        SECP256K1_FLAGS_BIT_COMPRESSION = (1 << 8),

        /** Flags to pass to secp256k1_context_create. */
        SECP256K1_CONTEXT_VERIFY = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY),
        SECP256K1_CONTEXT_SIGN = (SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN),
        SECP256K1_CONTEXT_NONE = (SECP256K1_FLAGS_TYPE_CONTEXT),

        /** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
        SECP256K1_EC_COMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION),
        SECP256K1_EC_UNCOMPRESSED = (SECP256K1_FLAGS_TYPE_COMPRESSION)
    }

}
