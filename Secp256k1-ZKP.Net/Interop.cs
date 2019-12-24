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


    [SuppressUnmanagedCodeSecurity]
    internal static class MuSigNative
    {
#if __IOS__ || (UNITY_IOS && !UNITY_EDITOR)
            private const string nativeLibrary = "__Internal";
#else
        private const string nativeLibrary = "libsecp256k1";
#endif
        //secp256k1_musig_partial_sig_adapt
        //secp256k1_musig_extract_secret_adaptor

        /// <summary>
        /// 
        /// </summary>
        /// <param name="flags"></param>
        /// <returns></returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern IntPtr secp256k1_context_create(uint flags);

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ctx"></param>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern void secp256k1_context_destroy(IntPtr ctx);

        /// <summary>
        /// Computes a combined public key and the hash of the given public keys.
        /// </summary>
        /// <param name="ctx">Pointer to a context object initialized for verification (cannot be NULL)</param>
        /// <param name="scratch">scratch space used to compute the combined pubkey by multiexponentiation. If NULL, an inefficient algorithm is used.</param>
        /// <param name="combined_pk">The MuSig-combined public key (cannot be NULL)</param>
        /// <param name="pk_hash32">If non-NULL, filled with the 32-byte hash of all input public keys in order to be used in `musig_session_initialize`.</param>
        /// <param name="pubkeys">input array of public keys to combine. The order is important; a different order will result in a different combined public key (cannot be NULL)</param>
        /// <param name="n_pubkeys">Length of pubkeys array</param>
        /// <returns>1 if the public keys were successfully combined, 0 otherwise.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_pubkey_combine(IntPtr ctx, IntPtr scratch, byte[] combined_pk, byte[] pk_hash32, IntPtr[] pubkeys, uint n_pubkeys);

        /// <summary>
        /// Initializes a signing session for a signer.
        /// </summary>
        /// <param name="ctx">Pointer to a context object, initialized for signing (cannot be NULL)</param>
        /// <param name="session">The session structure to initialize (cannot be NULL)</param>
        /// <param name="signers">An array of signers' data to be initialized. Array length must equal to `n_signers` (cannot be NULL)</param>
        /// <param name="nonce_commitment32">Filled with a 32-byte commitment to the generated nonce (cannot be NULL)</param>
        /// <param name="session_id32">A *unique* 32-byte ID to assign to this session (cannot be  NULL). If a non-unique session_id32 was given then a partial signature will LEAK THE SECRET KEY.</param>
        /// <param name="msg32">The 32-byte message to be signed. Shouldn't be NULL unless you require sharing nonce commitments before the message is known because it reduces nonce misuse resistance. If NULL, must be  set with `musig_session_get_public_nonce`.</param>
        /// <param name="combined_pk">The combined public key of all signers (cannot be NULL)</param>
        /// <param name="pk_hash32">the 32-byte hash of the signers' individual keys (cannot be NULL)</param>
        /// <param name="n_signers">length of signers array. Number of signers participating in the MuSig. Must be greater than 0 and at most 2^32 - 1.</param>
        /// <param name="my_index">Index of this signer in the signers array.</param>
        /// <param name="seckey">The signer's 32-byte secret key (cannot be NULL)</param>
        /// <returns>1: Session is successfully initialized. 0: Session could not be initialized: secret key or secret nonce overflow.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_session_initialize(IntPtr ctx, IntPtr session, IntPtr[] signers, byte[] nonce_commitment32, byte[] session_id32, byte[] msg32, byte[] combined_pk, byte[] pk_hash32, uint n_signers, uint my_index, byte[] seckey);

        /// <summary>
        /// Gets the signer's public nonce given a list of all signers' data with commitments.
        /// </summary>
        /// <param name="ctx">Pointer to a context object (cannot be NULL)</param>
        /// <param name="session">The signing session to get the nonce from (cannot be NULL)</param>
        /// <param name="signers">An array of signers' data initialized with `musig_session_initialize`. Array length must equal to `n_commitments` (cannot be NULL)</param>
        /// <param name="nonce">The nonce (cannot be NULL)</param>
        /// <param name="commitments">Array of 32-byte nonce commitments (cannot be NULL)</param>
        /// <param name="n_commitments">The length of commitments and signers array. Must be the total number of signers participating in the MuSig.</param>
        /// <param name="msg32">The 32-byte message to be signed. Must be NULL if already set with `musig_session_initialize` otherwise can not be NULL.</param>
        /// <returns>1: public nonce is written in nonce. 0: signer data is missing commitments or session isn't initialized for signing.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_session_get_public_nonce(IntPtr ctx, IntPtr session, IntPtr[] signers, byte[] nonce, IntPtr[] commitments, uint n_commitments, byte[] msg32);

        /// <summary>
        /// Initializes a verifier session that can be used for verifying nonce commitments
        /// and partial signatures. It does not have secret key material and therefore can not
        /// be used to create signatures.
        /// </summary>
        /// <param name="ctx">Pointer to a context object (cannot be NULL)</param>
        /// <param name="session">The session structure to initialize (cannot be NULL)</param>
        /// <param name="signers">An array of signers' data to be initialized. Array length must equal to `n_signers`(cannot be NULL)</param>
        /// <param name="msg32">The 32-byte message to be signed (cannot be NULL)</param>
        /// <param name="combined_pk">The combined public key of all signers (cannot be NULL)</param>
        /// <param name="pk_hash32">The 32-byte hash of the signers' individual keys (cannot be NULL)</param>
        /// <param name="commitments">Array of 32-byte nonce commitments. Array length must equal to `n_signers` (cannot be NULL)</param>
        /// <param name="n_signers">Length of signers and commitments array. Number of signers participating in the MuSig. Must be greater than 0 and at most 2^32 - 1.</param>
        /// <returns>1 when session is successfully initialized, 0 otherwise</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_session_initialize_verifier(IntPtr ctx, IntPtr session, IntPtr[] signers, byte[] msg32, byte[] combined_pk, byte[] pk_hash32, IntPtr[] commitments, uint n_signers);

        /// <summary>
        /// Checks a signer's public nonce against a commitment to said nonce, and update data structure if they match.
        /// </summary>
        /// <param name="ctx">Pointer to a context object (cannot be NULL)</param>
        /// <param name="signer">pointer to the signer data to update (cannot be NULL). Must have been used with `musig_session_get_public_nonce` or initialized with `musig_session_initialize_verifier`.</param>
        /// <param name="nonce">Signer's alleged public nonce (cannot be NULL)</param>
        /// <returns>1: Commitment was valid, data structure updated. 0: Commitment was invalid, nothing happened.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_set_nonce(IntPtr ctx, IntPtr signer, byte[] nonce);

        /// <summary>
        /// Updates a session with the combined public nonce of all signers. The combined public nonce is the sum of every signer's public nonce.
        /// </summary>
        /// <param name="ctx">Pointer to a context object (cannot be NULL)</param>
        /// <param name="session">Session to update with the combined public nonce (cannot be NULL)</param>
        /// <param name="signers">An array of signers' data, which must have had public nonces set with `musig_set_nonce`. Array length must equal to `n_signers` (cannot be NULL)</param>
        /// <param name="n_signers">The length of the signers array. Must be the total number of signers participating in the MuSig.</param>
        /// <param name="nonce_is_negated">A pointer to an integer that indicates if the combined public nonce had to be negated.</param>
        /// <param name="adaptor">Point to add to the combined public nonce. If NULL, nothing is added to the combined nonce.</param>
        /// <returns>1: Nonces are successfully combined. 0: A signer's nonce is missing</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_session_combine_nonces(IntPtr ctx, IntPtr session, IntPtr[] signers, uint n_signers, int nonce_is_negated, byte[] adaptor);

        /// <summary>
        /// Serialize a MuSig partial signature or adaptor signature.
        /// </summary>
        /// <param name="ctx">A secp256k1 context objec</param>
        /// <param name="out32">Pointer to a 32-byte array to store the serialized signature</param>
        /// <param name="sig">Pointer to the signature</param>
        /// <returns>1 When the signature could be serialized, 0 Otherwise</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_partial_signature_serialize(IntPtr ctx, byte[] out32, byte[] sig);

        /// <summary>
        /// Parse and verify a MuSig partial signature.
        /// </summary>
        /// <param name="ctx">A secp256k1 context object.</param>
        /// <param name="sig">Pointer to a signature object.</param>
        /// <param name="in32">Pointer to the 32-byte signature to be parsed.</param>
        /// <returns>1 When the signature could be parsed, 0 Otherwise.</returns>
        /// <remarks>After the call, sig will always be initialized. If parsing failed or the
        /// encoded numbers are out of range, signature verification with it is
        /// guaranteed to fail for every message and public key.</remarks>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_partial_signature_parse(IntPtr ctx, byte[] sig, byte[] in32);

        /// <summary>
        /// Produces a partial signature.
        /// </summary>
        /// <param name="ctx">Pointer to a context object (cannot be NULL)</param>
        /// <param name="session">Active signing session for which the combined nonce has been computed (cannot be NULL)</param>
        /// <param name="partial_sig">Partial signature (cannot be NULL)</param>
        /// <returns>1: Partial signature constructed. 0: Session in incorrect or inconsistent state.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_partial_sign(IntPtr ctx, IntPtr session, byte[] partial_sig);

        /// <summary>
        /// Checks that an individual partial signature verifies.
        /// </summary>
        /// <param name="ctx">Pointer to a context object (cannot be NULL)</param>
        /// <param name="session">Active session for which the combined nonce has been computed (cannot be NULL)</param>
        /// <param name="signer">Data for the signer who produced this signature (cannot be NULL)</param>
        /// <param name="partial_sig">Signature to verify (cannot be NULL)</param>
        /// <param name="pubkey">Public key of the signer who produced the signature (cannot be NULL)</param>
        /// <returns>1: Partial signature verifies. 0: Invalid signature or bad data.</returns>
        /// <remarks>This function is essential when using protocols with adaptor signatures.
        /// However, it is not essential for regular MuSig's, in the sense that if any
        /// partial signatures does not verify, the full signature will also not verify, so the
        /// problem will be caught. But this function allows determining the specific p
        /// who produced an invalid signature, so that signing can be restarted without them.</remarks>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_partial_sig_verify(IntPtr ctx, IntPtr session, IntPtr signer, byte[] partial_sig, byte[] pubkey);

        /// <summary>
        /// Combines partial signatures.
        /// </summary>
        /// <param name="ctx">pointer to a context object (cannot be NULL)</param>
        /// <param name="session">initialized session for which the combined nonce has been computed (cannot be NULL)</param>
        /// <param name="sig">complete signature (cannot be NULL)</param>
        /// <param name="partial_sigs">array of partial signatures to combine (cannot be NULL)</param>
        /// <param name="n_sigs">number of signatures in the partial_sigs array</param>
        /// <param name="tweak32">if `combined_pk` was tweaked with `ec_pubkey_tweak_add`
        /// after `musig_pubkey_combine` and before `musig_session_initialize` then
        /// the same tweak must be provided here in order to get a valid
        /// signature for the tweaked key. Otherwise `tweak` should be NULL.
        ///  If the tweak is larger than the group order or 0 this function will return 0. (can be NULL)</param>
        /// <returns>1: all partial signatures have values in range. Does NOT mean the resulting signature verifies. 0: Some partial signature had s/r out of range</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_partial_sig_combine(IntPtr ctx, IntPtr session, byte[] sig, IntPtr[] partial_sigs, uint n_sigs, IntPtr tweak32);

        /// <summary>
        /// Converts a partial signature to an adaptor signature by adding a given secret adaptor.
        /// </summary>
        /// <param name="ctx">Pointer to a context object (cannot be NULL)</param>
        /// <param name="adaptor_sig">Adaptor signature to produce (cannot be NULL)</param>
        /// <param name="partial_sig">Partial signature to tweak with secret adaptor (cannot be NULL)</param>
        /// <param name="sec_adaptor32">32-byte secret adaptor to add to the partial signature (cannot be NULL)</param>
        /// <param name="nonce_is_negated">The `nonce_is_negated` output of `musig_session_combine_nonces`</param>
        /// <returns>1: Signature and secret adaptor contained valid values. 0: Otherwise.</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_partial_sig_adapt(IntPtr ctx, byte[] adaptor_sig, byte[] partial_sig, byte[] sec_adaptor32, int nonce_is_negated);


        /// <summary>
        /// Extracts a secret adaptor from a MuSig, given all parties' partial
        /// signatures. This function will not fail unless given grossly invalid data; if it
        /// is merely given signatures that do not verify, the returned value will be
        /// nonsense. It is therefore important that all data be verified at earlier steps of
        /// any protocol that uses this function.
        /// </summary>
        /// <param name="ctx">pointer to a context object (cannot be NULL)</param>
        /// <param name="sec_adaptor32">32-byte secret adaptor (cannot be NULL)</param>
        /// <param name="sig">Complete 2-of-2 signature (cannot be NULL)</param>
        /// <param name="partial_sigs">Array of partial signatures (cannot be NULL)</param>
        /// <param name="n_partial_sigs">Number of elements in partial_sigs array</param>
        /// <param name="nonce_is_negated">The `nonce_is_negated` output of `musig_session_combine_nonces`</param>
        /// <returns>1: Signatures contained valid data such that an adaptor could be extracted. 0: Otherwise</returns>
        [DllImport(nativeLibrary, CallingConvention = CallingConvention.Cdecl)]
        internal static extern int secp256k1_musig_extract_secret_adaptor(IntPtr ctx, byte[] sec_adaptor32, byte[] sig, IntPtr[] partial_sigs, uint n_partial_sigs, int nonce_is_negated);
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
