using System;
using static Secp256k1_ZKP.Net.Secp256k1Native;

namespace Secp256k1_ZKP.Net
{
    public class MuSig : IDisposable
    {
        public IntPtr Context { get; private set; }

        public MuSig()
        {
            Context = secp256k1_context_create((uint)(Flags.SECP256K1_CONTEXT_SIGN | Flags.SECP256K1_CONTEXT_VERIFY));
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
