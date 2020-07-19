using System;
using System.Linq;
using System.Reflection.Emit;
using System.Runtime.InteropServices;

namespace Secp256k1Zkp
{
    public unsafe class Util
    {
        public delegate void MemCpyFunction(void* des, void* src, uint bytes);
        public static readonly MemCpyFunction MemCpy;

        static Util()
        {
            var dynamicMemCpyMethod = new DynamicMethod
            (
                "MemCpy",
                typeof(void),
                new[] { typeof(void*), typeof(void*), typeof(uint) },
                typeof(MLSAG)
            );

            var ilGenerator = dynamicMemCpyMethod.GetILGenerator();

            ilGenerator.Emit(OpCodes.Ldarg_0);
            ilGenerator.Emit(OpCodes.Ldarg_1);
            ilGenerator.Emit(OpCodes.Ldarg_2);

            ilGenerator.Emit(OpCodes.Cpblk);
            ilGenerator.Emit(OpCodes.Ret);

            MemCpy = (MemCpyFunction)dynamicMemCpyMethod.CreateDelegate(typeof(MemCpyFunction));
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static IntPtr ToIntPtr(byte[] data)
        {
            var ptr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, ptr, data.Length);

            return ptr;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static IntPtr ToIntPtr(IntPtr[] data)
        {
            var ptr = Marshal.AllocHGlobal(data.Length);
            Marshal.Copy(data, 0, ptr, data.Length);

            return ptr;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static IntPtr[] ToIntPtrs(Span<byte[]> data)
        {
            int size = data.Length;
            IntPtr[] subarrays = new IntPtr[size];

            foreach (var outs in data.ToArray().Select((x, i) => (x, i)))
            {
                if (outs.x == null)
                    continue;

                subarrays[outs.i] = ToIntPtr(outs.x);
            }

            return subarrays;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ptr"></param>
        /// <param name="size"></param>
        /// <returns></returns>
        public static byte[] ReversePtr(IntPtr ptr, int size = 32)
        {
            byte[] managedArray = new byte[size];
            Marshal.Copy(ptr, managedArray, 0, size);

            return managedArray;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="min"></param>
        /// <param name="max"></param>
        /// <returns></returns>
        public static int Rand(int min = 1, int max = 32767)
        {
            var random = new Random();
            return random.Next(min, max);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bytes"></param>
        /// <returns></returns>
        public static string ByteToHex(byte[] bytes)
        {
            char[] c = new char[bytes.Length * 2];
            int b;
            for (int i = 0; i < bytes.Length; i++)
            {
                b = bytes[i] >> 4;
                c[i * 2] = (char)(55 + b + (((b - 10) >> 31) & -7));
                b = bytes[i] & 0xF;
                c[i * 2 + 1] = (char)(55 + b + (((b - 10) >> 31) & -7));
            }
            return new string(c);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="s"></param>
        /// <returns></returns>
        public static byte[] HexToByte(string s)
        {
            byte[] bytes = new byte[s.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                int hi = s[i * 2] - 65;
                hi = hi + 10 + ((hi >> 31) & 7);

                int lo = s[i * 2 + 1] - 65;
                lo = lo + 10 + ((lo >> 31) & 7) & 0x0f;

                bytes[i] = (byte)(lo | hi << 4);
            }
            return bytes;
        }
    }
}
