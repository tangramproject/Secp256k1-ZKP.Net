using System;
using System.Security.Cryptography;
using static Secp256k1Zkp.Secp256k1Native;

namespace Secp256k1Zkp
{
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
        public KeyPair GenerateKeyPair(bool compressPuplicKey = false)
        {
            var privateKey = CreatePrivateKey();
            var publicKey = CreatePublicKey(privateKey);

            if (compressPuplicKey)
            {
                publicKey = SerializePublicKey(publicKey, Flags.SECP256K1_EC_COMPRESSED);
            }

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="seed"></param>
        /// <param name="compressPuplicKey"></param>
        /// <returns></returns>
        public KeyPair GenerateKeyPair(byte[] seed, bool compressPuplicKey = false)
        {
            var sha256 = HashAlgorithm.Create("SHA-256");
            var privateKey = sha256.ComputeHash(seed);
            var publicKey = CreatePublicKey(privateKey);

            if (compressPuplicKey)
            {
                publicKey = SerializePublicKey(publicKey, Flags.SECP256K1_EC_COMPRESSED);
            }

            return new KeyPair(publicKey, privateKey);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public byte[] PubKeyParse(byte[] pubKey, int size)
        {
            if (pubKey.Length < Constant.PUBLIC_KEY_COMPRESSED_SIZE)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_COMPRESSED_SIZE} bytes");

            if (pubKey.Length > Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            var parsedOut = new byte[size];
            return secp256k1_ec_pubkey_parse(Context, parsedOut, pubKey, size) == 1 ? parsedOut : null;
        }

        /// <summary>
        /// Gets the secret key.
        /// </summary>
        /// <returns>The secret key.</returns>
        public byte[] CreatePrivateKey()
        {
            var key = new byte[32];
            var rnd = RandomNumberGenerator.Create();

            do { rnd.GetBytes(key); }
            while (!VerifySecKey(key));

            return key;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public byte[] RandomSeed(int size = 16)
        {
            var random = RandomNumberGenerator.Create();
            var bytes = new byte[size];

            random.GetNonZeroBytes(bytes);

            return bytes;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public byte[] Randomize32()
        {
            var seed32 = RandomSeed(32);
            return secp256k1_context_randomize(Context, seed32) == 1 ? seed32 : null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="seckey"></param>
        /// <returns></returns>
        public byte[] CreatePublicKey(byte[] seckey, bool compress = false)
        {
            if (seckey.Length != Constant.SECRET_KEY_SIZE)
                throw new ArgumentException($"{nameof(seckey)} must be {Constant.SECRET_KEY_SIZE} bytes");

            bool init = false;
            var pubOut = new byte[64];

            if (secp256k1_ec_pubkey_create(Context, pubOut, seckey) == 1)
            {
                init = true;

                if (compress)
                {
                    return SerializePublicKey(pubOut, Flags.SECP256K1_EC_COMPRESSED);
                }
            }

            return init == true ? pubOut : null;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="pubKey"></param>
        /// <param name="flags"></param>
        /// <returns></returns>
        public byte[] SerializePublicKey(byte[] pubKey, Flags flags = Flags.SECP256K1_EC_UNCOMPRESSED)
        {
            if (pubKey.Length < Constant.PUBLIC_KEY_SIZE)
                throw new ArgumentException($"{nameof(pubKey)} must be {Constant.PUBLIC_KEY_SIZE} bytes");

            bool compressed = flags.HasFlag(Flags.SECP256K1_EC_COMPRESSED);
            int serializedPubKeyLength = compressed ? Constant.SERIALIZED_COMPRESSED_PUBKEY_LENGTH : Constant.SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH;
            uint newLength = (uint)serializedPubKeyLength;

            var outPub = new byte[serializedPubKeyLength];
            return secp256k1_ec_pubkey_serialize(Context, outPub, ref newLength, pubKey, (uint)flags) == 1 ? outPub : null;
        }

        /// <summary>
        /// Sign the specified msg32 and seckey.
        /// </summary>
        /// <returns>The sign.</returns>
        /// <param name="msg32">Msg32.</param>
        /// <param name="seckey">Seckey.</param>
        public byte[] Sign(byte[] msg32, byte[] seckey)
        {
            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (seckey.Length != Constant.SECRET_KEY_SIZE)
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
            if (sig.Length != Constant.SIGNATURE_SIZE)
                throw new ArgumentException($"{nameof(sig)} must be {Constant.SIGNATURE_SIZE} bytes");

            if (msg32.Length != Constant.MESSAGE_SIZE)
                throw new ArgumentException($"{nameof(msg32)} must be {Constant.MESSAGE_SIZE} bytes");

            if (pubkey.Length < Constant.PUBLIC_KEY_COMPRESSED_SIZE)
                throw new ArgumentException($"{nameof(pubkey)} must be {Constant.PUBLIC_KEY_COMPRESSED_SIZE} bytes");

            if (pubkey.Length > Constant.PUBLIC_KEY_SIZE)
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
            if (seckey.Length != Constant.SECRET_KEY_SIZE)
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
