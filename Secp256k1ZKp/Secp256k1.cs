using System;
using static Secp256k1Zkp.Secp256k1Native;

namespace Secp256k1Zkp
{
    public struct KeyPair
    {
        public byte[] privateKey;
        public byte[] publicKey;

        public KeyPair(byte[] privateKey, byte[] publicKey)
        {
            this.privateKey = privateKey;
            this.publicKey = publicKey;
        }
    }

    public class Secp256k1 : IDisposable
    {
        public IntPtr Context { get; private set; }

        public Secp256k1()
        {
            Context = secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public KeyPair GenerateKeyPair()
        {
            var privateKey = GetSecretKey();
            var publicKey = PublicKeyCreate(privateKey);
            return new KeyPair(privateKey, publicKey);
        }

        /// <summary>
        /// Gets the secret key.
        /// </summary>
        /// <returns>The secret key.</returns>
        public byte[] GetSecretKey()
        {
            var key = new byte[32];
            var rnd = System.Security.Cryptography.RandomNumberGenerator.Create();

            do { rnd.GetBytes(key); }
            while (!VerifySecKey(key));

            return key;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="seckey"></param>
        /// <returns></returns>
        public byte[] PublicKeyCreate(byte[] seckey)
        {
            var pubOut = new byte[64];
            if (secp256k1_ec_pubkey_create(Context, pubOut, seckey) == 1)
                return pubOut;

            return null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        public byte[] PubKeySerialize(byte[] pubKey, Flags flags = Flags.SECP256K1_EC_UNCOMPRESSED)
        {
            if (pubKey.Length < Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            bool compressed = flags.HasFlag(Flags.SECP256K1_EC_COMPRESSED);
            int serializedPubKeyLength = compressed ? Constant.SERIALIZED_COMPRESSED_PUBKEY_LENGTH : Constant.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            uint newLength = (uint)serializedPubKeyLength;

            var outPub = new byte[serializedPubKeyLength];
            if (secp256k1_ec_pubkey_serialize(Context, outPub, ref newLength, pubKey, (uint)flags) == 1)
                return outPub;

            return null;
        }

        /// <summary>
        /// Sign the specified msg32 and seckey.
        /// </summary>
        /// <returns>The sign.</returns>
        /// <param name="msg32">Msg32.</param>
        /// <param name="seckey">Seckey.</param>
        public byte[] Sign(byte[] msg32, byte[] seckey)
        {
            if (msg32.Length < Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (seckey.Length < Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(seckey)} must be {Constant.SECRET_KEY_SIZE} bytes");

            var sigOut = new byte[64];
            return secp256k1_ecdsa_sign(Context, sigOut, msg32, seckey, IntPtr.Zero, (IntPtr)null) == 1 ? sigOut : null;
        }

        /// <summary>
        /// Verify the specified sig, msg32 and pubkey.
        /// </summary>
        /// <returns>The verify.</returns>
        /// <param name="sig">Sig.</param>
        /// <param name="msg32">Msg32.</param>
        /// <param name="pubkey">Pubkey.</param>
        public bool Verify(byte[] sig, byte[] msg32, byte[] pubkey)
        {
            if (sig.Length < Constant.SIGNATURE_SIZE)
                throw new ArgumentException($"{nameof(sig)} must be {Constant.SIGNATURE_SIZE} bytes");

            if (msg32.Length < Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");


            if (pubkey.Length < Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubkey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            return secp256k1_ecdsa_verify(Context, sig, msg32, pubkey) == 1;
        }

        /// <summary>
        /// Verifies the sec key.
        /// </summary>
        /// <returns><c>true</c>, if sec key was verifyed, <c>false</c> otherwise.</returns>
        /// <param name="seckey">Seckey.</param>
        public bool VerifySecKey(byte[] seckey)
        {
            if (seckey.Length < Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(seckey)} must be {Constant.SECRET_KEY_SIZE} bytes");

            return secp256k1_ec_seckey_verify(Context, seckey) == 1;
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
