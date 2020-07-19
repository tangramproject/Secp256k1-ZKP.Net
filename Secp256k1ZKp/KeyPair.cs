using System;
using Isopoh.Cryptography.SecureArray;

namespace Secp256k1Zkp
{
    public class KeyPair : IDisposable
    {
        private readonly byte[] _publicKey;
        private readonly SecureArray<byte> _privateKey;

        public KeyPair(byte[] publicKey, byte[] privateKey)
        {
            if (privateKey.Length % 16 != 0)
                throw new ArgumentOutOfRangeException("Private Key length must be a multiple of 16 bytes.");

            _publicKey = publicKey;
            _privateKey = new SecureArray<byte>(32, SecureArrayType.ZeroedPinnedAndNoSwap);

            Array.Copy(privateKey, _privateKey.Buffer, privateKey.Length);
            Array.Clear(privateKey, 0, 32);
        }

        ~KeyPair()
        {
            Dispose();
        }

        public byte[] PublicKey => _publicKey;

        public byte[] PrivateKey => _privateKey.Buffer;

        public void Dispose() => _privateKey?.Dispose();
    }
}
