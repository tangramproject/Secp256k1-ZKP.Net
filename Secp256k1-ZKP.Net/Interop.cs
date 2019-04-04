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
        internal static extern int secp256k1_rangeproof_info(IntPtr ctx, int exp, int mantissa, ulong min_value, ulong max_value, byte[] proof, uint plen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_rangeproof_rewind(IntPtr ctx, byte[] blind_out, ulong value_out, byte[] message_out, uint outlen, byte[] nonce, ulong min_value, 
            ulong max_value, byte[] commit, byte[] proof, uint plen, byte[] extra_commit, uint extra_commit_len, byte[] gen);
           
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_rangeproof_verify(IntPtr ctx, ulong min_value, ulong max_value, byte[] commit, byte[] proof, uint plen, byte[] extra_commit, uint extra_commit_len, byte[] gen);

        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_rangeproof_sign(IntPtr ctx, byte[] proof, uint plen, ulong min_value, byte[] commit, byte[] blind, byte[] nonce, int exp, int min_bits, 
            ulong value, byte[] message, uint msg_len, byte[] extra_commit, uint extra_commit_len, byte[] gen);

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
