﻿using System;
namespace Secp256k1_ZKP.Net
{
    public static class Constant
    {
        public const int GENERATOR_H_LENGTH = 64;
        public const int GENERATOR_G_LENGTH = 64;
        public const int SEED_LENGTH = 32;
        public const int BLIND_LENGTH = 32;
        public const int SERIALIZED_UNCOMPRESSED_PUBKEY_LENGTH = 65;
        public const int SERIALIZED_COMPRESSED_PUBKEY_LENGTH = 33;

        // https://github.com/mimblewimble/rust-secp256k1-zkp/blob/master/src/constants.rs
        //
        public const int PEDERSEN_COMMITMENT_SIZE = 33;
        public const int PEDERSEN_COMMITMENT_SIZE_INTERNAL = 64;
        public const int SECRET_KEY_SIZE = 32;
        public const int PUBLIC_KEY_SIZE = 64;
        public const int MESSAGE_SIZE = 32;
        public const int SIGNATURE_SIZE = 64;
        public const int MAX_SIGNATURE_SIZE = 72;
        public const int COMPACT_SIGNATURE_SIZE = 64;

        // Generator G
        public static byte[] GENERATOR_G = {
            0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac,
            0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
            0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
            0x48, 0x3a, 0xda, 0x77, 0x26, 0xa3, 0xc4, 0x65,
            0x5d, 0xa4, 0xfb, 0xfc, 0x0e, 0x11, 0x08, 0xa8,
            0xfd, 0x17, 0xb4, 0x48, 0xa6, 0x85, 0x54, 0x19,
            0x9c, 0x47, 0xd0, 0x8f, 0xfb, 0x10, 0xd4, 0xb8
        };

        // Generator H(as compressed curve point (3))
        public static byte[] GENERATOR_H = {
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54,
            0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
            0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5,
            0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
            0x31, 0xd3, 0xc6, 0x86, 0x39, 0x73, 0x92, 0x6e,
            0x04, 0x9e, 0x63, 0x7c, 0xb1, 0xb5, 0xf4, 0x0a,
            0x36, 0xda, 0xc2, 0x8a, 0xf1, 0x76, 0x69, 0x68,
            0xc3, 0x0c, 0x23, 0x13, 0xf3, 0xa3, 0x89, 0x04
        };

        // Raw bytes for generator J as public key
        // This is the sha256 of the sha256 of 'g' after DER encoding (without compression),
        // which happens to be a point on the curve.
        // sage: gen_h =  hashlib.sha256('0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8'.decode('hex'))
        // sage: gen_j_input = gen_h.hexdigest()
        // sage: gen_j =  hashlib.sha256(gen_j_input.decode('hex'))
        // sage: G3 = EllipticCurve ([F (0), F (7)]).lift_x(int(gen_j.hexdigest(),16))
        // sage: '%x %x'%G3.xy()
        public static byte[] GENERATOR_PUB_J_RAW = {
            0x5f, 0x15, 0x21, 0x36, 0x93, 0x93, 0x01, 0x2a,
            0x8d, 0x8b, 0x39, 0x7e, 0x9b, 0xf4, 0x54, 0x29,
            0x2f, 0x5a, 0x1b, 0x3d, 0x38, 0x85, 0x16, 0xc2,
            0xf3, 0x03, 0xfc, 0x95, 0x67, 0xf5, 0x60, 0xb8,
            0x3a, 0xc4, 0xc5, 0xa6, 0xdc, 0xa2, 0x01, 0x59,
            0xfc, 0x56, 0xcf, 0x74, 0x9a, 0xa6, 0xa5, 0x65,
            0x31, 0x6a, 0xa5, 0x03, 0x74, 0x42, 0x3f, 0x42,
            0x53, 0x8f, 0xaa, 0x2c, 0xd3, 0x09, 0x3f, 0xa4
        };

    }
}