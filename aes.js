// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
//
// AES JAVASCRIPT IMPLEMENTATION
// Author: Dr. Franz Kollmann 2009 - 2018
//
//    The following javascript code can be freely used.
//    The code is based on the original AES/Rijndael specification of the NIST.
//    Some improvements (e.g. predefined array values instead of calculations) are included to achieve better performance results.
//    Although the code was created with care, no guarantee/warranty of flawlessness and correctness will be given.
//
//    USAGE
//      ENCRYPTION: Use encryptCTR(m, k, iv) or encryptCBC(m, k, iv) to encrypt message m with key k and initial vector iv   where m, k, iv represent byte arrays (convert your data to byte array accordingly)
//      DECRYPTION: Use decryptCTR(c, k, iv) or decryptCBC(c, k, iv) to decrypt cipher  c with key k and initial vector iv   where c, k, iv represent byte arrays (convert your data to byte array accordingly)
//
// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

// ------------ INTERNAL ARRAYS AND FUNCTIONS: YOU MAY NOT USE THEM IN YOUR JAVASCRIPT CODE ------------------------------------------------------------------------------------------------------------------------------------------
  var sbox = [
       99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118,
      202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192,
      183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21,
        4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117,
        9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132,
       83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207,
      208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168,
       81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210,
      205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115,
       96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219,
      224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121,
      231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8,
      186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138,
      112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158,
      225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223,
      140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22];

  var invsbox = [
       82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251,
      124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203,
       84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78,
        8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37,
      114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146,
      108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132,
      144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6,
      208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107,
       58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115,
      150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110,
       71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27,
      252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244,
       31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95,
       96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239,
      160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97,
       23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125];

   var twoTimes = [
       0x00, 0x02, 0x04, 0x06, 0x08, 0x0A, 0x0C, 0x0E, 0x10, 0x12, 0x14, 0x16, 0x18, 0x1A, 0x1C, 0x1E,
       0x20, 0x22, 0x24, 0x26, 0x28, 0x2A, 0x2C, 0x2E, 0x30, 0x32, 0x34, 0x36, 0x38, 0x3A, 0x3C, 0x3E,
       0x40, 0x42, 0x44, 0x46, 0x48, 0x4A, 0x4C, 0x4E, 0x50, 0x52, 0x54, 0x56, 0x58, 0x5A, 0x5C, 0x5E,
       0x60, 0x62, 0x64, 0x66, 0x68, 0x6A, 0x6C, 0x6E, 0x70, 0x72, 0x74, 0x76, 0x78, 0x7A, 0x7C, 0x7E,
       0x80, 0x82, 0x84, 0x86, 0x88, 0x8A, 0x8C, 0x8E, 0x90, 0x92, 0x94, 0x96, 0x98, 0x9A, 0x9C, 0x9E,
       0xA0, 0xA2, 0xA4, 0xA6, 0xA8, 0xAA, 0xAC, 0xAE, 0xB0, 0xB2, 0xB4, 0xB6, 0xB8, 0xBA, 0xBC, 0xBE,
       0xC0, 0xC2, 0xC4, 0xC6, 0xC8, 0xCA, 0xCC, 0xCE, 0xD0, 0xD2, 0xD4, 0xD6, 0xD8, 0xDA, 0xDC, 0xDE,
       0xE0, 0xE2, 0xE4, 0xE6, 0xE8, 0xEA, 0xEC, 0xEE, 0xF0, 0xF2, 0xF4, 0xF6, 0xF8, 0xFA, 0xFC, 0xFE,
       0x1B, 0x19, 0x1F, 0x1D, 0x13, 0x11, 0x17, 0x15, 0x0B, 0x09, 0x0F, 0x0D, 0x03, 0x01, 0x07, 0x05,
       0x3B, 0x39, 0x3F, 0x3D, 0x33, 0x31, 0x37, 0x35, 0x2B, 0x29, 0x2F, 0x2D, 0x23, 0x21, 0x27, 0x25,
       0x5B, 0x59, 0x5F, 0x5D, 0x53, 0x51, 0x57, 0x55, 0x4B, 0x49, 0x4F, 0x4D, 0x43, 0x41, 0x47, 0x45,
       0x7B, 0x79, 0x7F, 0x7D, 0x73, 0x71, 0x77, 0x75, 0x6B, 0x69, 0x6F, 0x6D, 0x63, 0x61, 0x67, 0x65,
       0x9B, 0x99, 0x9F, 0x9D, 0x93, 0x91, 0x97, 0x95, 0x8B, 0x89, 0x8F, 0x8D, 0x83, 0x81, 0x87, 0x85,
       0xBB, 0xB9, 0xBF, 0xBD, 0xB3, 0xB1, 0xB7, 0xB5, 0xAB, 0xA9, 0xAF, 0xAD, 0xA3, 0xA1, 0xA7, 0xA5,
       0xDB, 0xD9, 0xDF, 0xDD, 0xD3, 0xD1, 0xD7, 0xD5, 0xCB, 0xC9, 0xCF, 0xCD, 0xC3, 0xC1, 0xC7, 0xC5,
       0xFB, 0xF9, 0xFF, 0xFD, 0xF3, 0xF1, 0xF7, 0xF5, 0xEB, 0xE9, 0xEF, 0xED, 0xE3, 0xE1, 0xE7, 0xE5];

   var threeTimes = [
       0x00, 0x03, 0x06, 0x05, 0x0C, 0x0F, 0x0A, 0x09, 0x18, 0x1B, 0x1E, 0x1D, 0x14, 0x17, 0x12, 0x11,
       0x30, 0x33, 0x36, 0x35, 0x3C, 0x3F, 0x3A, 0x39, 0x28, 0x2B, 0x2E, 0x2D, 0x24, 0x27, 0x22, 0x21,
       0x60, 0x63, 0x66, 0x65, 0x6C, 0x6F, 0x6A, 0x69, 0x78, 0x7B, 0x7E, 0x7D, 0x74, 0x77, 0x72, 0x71,
       0x50, 0x53, 0x56, 0x55, 0x5C, 0x5F, 0x5A, 0x59, 0x48, 0x4B, 0x4E, 0x4D, 0x44, 0x47, 0x42, 0x41,
       0xC0, 0xC3, 0xC6, 0xC5, 0xCC, 0xCF, 0xCA, 0xC9, 0xD8, 0xDB, 0xDE, 0xDD, 0xD4, 0xD7, 0xD2, 0xD1,
       0xF0, 0xF3, 0xF6, 0xF5, 0xFC, 0xFF, 0xFA, 0xF9, 0xE8, 0xEB, 0xEE, 0xED, 0xE4, 0xE7, 0xE2, 0xE1,
       0xA0, 0xA3, 0xA6, 0xA5, 0xAC, 0xAF, 0xAA, 0xA9, 0xB8, 0xBB, 0xBE, 0xBD, 0xB4, 0xB7, 0xB2, 0xB1,
       0x90, 0x93, 0x96, 0x95, 0x9C, 0x9F, 0x9A, 0x99, 0x88, 0x8B, 0x8E, 0x8D, 0x84, 0x87, 0x82, 0x81,
       0x9B, 0x98, 0x9D, 0x9E, 0x97, 0x94, 0x91, 0x92, 0x83, 0x80, 0x85, 0x86, 0x8F, 0x8C, 0x89, 0x8A,
       0xAB, 0xA8, 0xAD, 0xAE, 0xA7, 0xA4, 0xA1, 0xA2, 0xB3, 0xB0, 0xB5, 0xB6, 0xBF, 0xBC, 0xB9, 0xBA,
       0xFB, 0xF8, 0xFD, 0xFE, 0xF7, 0xF4, 0xF1, 0xF2, 0xE3, 0xE0, 0xE5, 0xE6, 0xEF, 0xEC, 0xE9, 0xEA,
       0xCB, 0xC8, 0xCD, 0xCE, 0xC7, 0xC4, 0xC1, 0xC2, 0xD3, 0xD0, 0xD5, 0xD6, 0xDF, 0xDC, 0xD9, 0xDA,
       0x5B, 0x58, 0x5D, 0x5E, 0x57, 0x54, 0x51, 0x52, 0x43, 0x40, 0x45, 0x46, 0x4F, 0x4C, 0x49, 0x4A,
       0x6B, 0x68, 0x6D, 0x6E, 0x67, 0x64, 0x61, 0x62, 0x73, 0x70, 0x75, 0x76, 0x7F, 0x7C, 0x79, 0x7A,
       0x3B, 0x38, 0x3D, 0x3E, 0x37, 0x34, 0x31, 0x32, 0x23, 0x20, 0x25, 0x26, 0x2F, 0x2C, 0x29, 0x2A,
       0x0B, 0x08, 0x0D, 0x0E, 0x07, 0x04, 0x01, 0x02, 0x13, 0x10, 0x15, 0x16, 0x1F, 0x1C, 0x19, 0x1A];

   var fourteenTimes = [
       0x00, 0x0E, 0x1C, 0x12, 0x38, 0x36, 0x24, 0x2A, 0x70, 0x7E, 0x6C, 0x62, 0x48, 0x46, 0x54, 0x5A,
       0xE0, 0xEE, 0xFC, 0xF2, 0xD8, 0xD6, 0xC4, 0xCA, 0x90, 0x9E, 0x8C, 0x82, 0xA8, 0xA6, 0xB4, 0xBA,
       0xDB, 0xD5, 0xC7, 0xC9, 0xE3, 0xED, 0xFF, 0xF1, 0xAB, 0xA5, 0xB7, 0xB9, 0x93, 0x9D, 0x8F, 0x81,
       0x3B, 0x35, 0x27, 0x29, 0x03, 0x0D, 0x1F, 0x11, 0x4B, 0x45, 0x57, 0x59, 0x73, 0x7D, 0x6F, 0x61,
       0xAD, 0xA3, 0xB1, 0xBF, 0x95, 0x9B, 0x89, 0x87, 0xDD, 0xD3, 0xC1, 0xCF, 0xE5, 0xEB, 0xF9, 0xF7,
       0x4D, 0x43, 0x51, 0x5F, 0x75, 0x7B, 0x69, 0x67, 0x3D, 0x33, 0x21, 0x2F, 0x05, 0x0B, 0x19, 0x17,
       0x76, 0x78, 0x6A, 0x64, 0x4E, 0x40, 0x52, 0x5C, 0x06, 0x08, 0x1A, 0x14, 0x3E, 0x30, 0x22, 0x2C,
       0x96, 0x98, 0x8A, 0x84, 0xAE, 0xA0, 0xB2, 0xBC, 0xE6, 0xE8, 0xFA, 0xF4, 0xDE, 0xD0, 0xC2, 0xCC,
       0x41, 0x4F, 0x5D, 0x53, 0x79, 0x77, 0x65, 0x6B, 0x31, 0x3F, 0x2D, 0x23, 0x09, 0x07, 0x15, 0x1B,
       0xA1, 0xAF, 0xBD, 0xB3, 0x99, 0x97, 0x85, 0x8B, 0xD1, 0xDF, 0xCD, 0xC3, 0xE9, 0xE7, 0xF5, 0xFB,
       0x9A, 0x94, 0x86, 0x88, 0xA2, 0xAC, 0xBE, 0xB0, 0xEA, 0xE4, 0xF6, 0xF8, 0xD2, 0xDC, 0xCE, 0xC0,
       0x7A, 0x74, 0x66, 0x68, 0x42, 0x4C, 0x5E, 0x50, 0x0A, 0x04, 0x16, 0x18, 0x32, 0x3C, 0x2E, 0x20,
       0xEC, 0xE2, 0xF0, 0xFE, 0xD4, 0xDA, 0xC8, 0xC6, 0x9C, 0x92, 0x80, 0x8E, 0xA4, 0xAA, 0xB8, 0xB6,
       0x0C, 0x02, 0x10, 0x1E, 0x34, 0x3A, 0x28, 0x26, 0x7C, 0x72, 0x60, 0x6E, 0x44, 0x4A, 0x58, 0x56,
       0x37, 0x39, 0x2B, 0x25, 0x0F, 0x01, 0x13, 0x1D, 0x47, 0x49, 0x5B, 0x55, 0x7F, 0x71, 0x63, 0x6D,
       0xD7, 0xD9, 0xCB, 0xC5, 0xEF, 0xE1, 0xF3, 0xFD, 0xA7, 0xA9, 0xBB, 0xB5, 0x9F, 0x91, 0x83, 0x8D];

   var elevenTimes = [
       0x00, 0x0B, 0x16, 0x1D, 0x2C, 0x27, 0x3A, 0x31, 0x58, 0x53, 0x4E, 0x45, 0x74, 0x7F, 0x62, 0x69,
       0xB0, 0xBB, 0xA6, 0xAD, 0x9C, 0x97, 0x8A, 0x81, 0xE8, 0xE3, 0xFE, 0xF5, 0xC4, 0xCF, 0xD2, 0xD9,
       0x7B, 0x70, 0x6D, 0x66, 0x57, 0x5C, 0x41, 0x4A, 0x23, 0x28, 0x35, 0x3E, 0x0F, 0x04, 0x19, 0x12,
       0xCB, 0xC0, 0xDD, 0xD6, 0xE7, 0xEC, 0xF1, 0xFA, 0x93, 0x98, 0x85, 0x8E, 0xBF, 0xB4, 0xA9, 0xA2,
       0xF6, 0xFD, 0xE0, 0xEB, 0xDA, 0xD1, 0xCC, 0xC7, 0xAE, 0xA5, 0xB8, 0xB3, 0x82, 0x89, 0x94, 0x9F,
       0x46, 0x4D, 0x50, 0x5B, 0x6A, 0x61, 0x7C, 0x77, 0x1E, 0x15, 0x08, 0x03, 0x32, 0x39, 0x24, 0x2F,
       0x8D, 0x86, 0x9B, 0x90, 0xA1, 0xAA, 0xB7, 0xBC, 0xD5, 0xDE, 0xC3, 0xC8, 0xF9, 0xF2, 0xEF, 0xE4,
       0x3D, 0x36, 0x2B, 0x20, 0x11, 0x1A, 0x07, 0x0C, 0x65, 0x6E, 0x73, 0x78, 0x49, 0x42, 0x5F, 0x54,
       0xF7, 0xFC, 0xE1, 0xEA, 0xDB, 0xD0, 0xCD, 0xC6, 0xAF, 0xA4, 0xB9, 0xB2, 0x83, 0x88, 0x95, 0x9E,
       0x47, 0x4C, 0x51, 0x5A, 0x6B, 0x60, 0x7D, 0x76, 0x1F, 0x14, 0x09, 0x02, 0x33, 0x38, 0x25, 0x2E,
       0x8C, 0x87, 0x9A, 0x91, 0xA0, 0xAB, 0xB6, 0xBD, 0xD4, 0xDF, 0xC2, 0xC9, 0xF8, 0xF3, 0xEE, 0xE5,
       0x3C, 0x37, 0x2A, 0x21, 0x10, 0x1B, 0x06, 0x0D, 0x64, 0x6F, 0x72, 0x79, 0x48, 0x43, 0x5E, 0x55,
       0x01, 0x0A, 0x17, 0x1C, 0x2D, 0x26, 0x3B, 0x30, 0x59, 0x52, 0x4F, 0x44, 0x75, 0x7E, 0x63, 0x68,
       0xB1, 0xBA, 0xA7, 0xAC, 0x9D, 0x96, 0x8B, 0x80, 0xE9, 0xE2, 0xFF, 0xF4, 0xC5, 0xCE, 0xD3, 0xD8,
       0x7A, 0x71, 0x6C, 0x67, 0x56, 0x5D, 0x40, 0x4B, 0x22, 0x29, 0x34, 0x3F, 0x0E, 0x05, 0x18, 0x13,
       0xCA, 0xC1, 0xDC, 0xD7, 0xE6, 0xED, 0xF0, 0xFB, 0x92, 0x99, 0x84, 0x8F, 0xBE, 0xB5, 0xA8, 0xA3];

   var thirteenTimes = [
       0x00, 0x0D, 0x1A, 0x17, 0x34, 0x39, 0x2E, 0x23, 0x68, 0x65, 0x72, 0x7F, 0x5C, 0x51, 0x46, 0x4B,
       0xD0, 0xDD, 0xCA, 0xC7, 0xE4, 0xE9, 0xFE, 0xF3, 0xB8, 0xB5, 0xA2, 0xAF, 0x8C, 0x81, 0x96, 0x9B,
       0xBB, 0xB6, 0xA1, 0xAC, 0x8F, 0x82, 0x95, 0x98, 0xD3, 0xDE, 0xC9, 0xC4, 0xE7, 0xEA, 0xFD, 0xF0,
       0x6B, 0x66, 0x71, 0x7C, 0x5F, 0x52, 0x45, 0x48, 0x03, 0x0E, 0x19, 0x14, 0x37, 0x3A, 0x2D, 0x20,
       0x6D, 0x60, 0x77, 0x7A, 0x59, 0x54, 0x43, 0x4E, 0x05, 0x08, 0x1F, 0x12, 0x31, 0x3C, 0x2B, 0x26,
       0xBD, 0xB0, 0xA7, 0xAA, 0x89, 0x84, 0x93, 0x9E, 0xD5, 0xD8, 0xCF, 0xC2, 0xE1, 0xEC, 0xFB, 0xF6,
       0xD6, 0xDB, 0xCC, 0xC1, 0xE2, 0xEF, 0xF8, 0xF5, 0xBE, 0xB3, 0xA4, 0xA9, 0x8A, 0x87, 0x90, 0x9D,
       0x06, 0x0B, 0x1C, 0x11, 0x32, 0x3F, 0x28, 0x25, 0x6E, 0x63, 0x74, 0x79, 0x5A, 0x57, 0x40, 0x4D,
       0xDA, 0xD7, 0xC0, 0xCD, 0xEE, 0xE3, 0xF4, 0xF9, 0xB2, 0xBF, 0xA8, 0xA5, 0x86, 0x8B, 0x9C, 0x91,
       0x0A, 0x07, 0x10, 0x1D, 0x3E, 0x33, 0x24, 0x29, 0x62, 0x6F, 0x78, 0x75, 0x56, 0x5B, 0x4C, 0x41,
       0x61, 0x6C, 0x7B, 0x76, 0x55, 0x58, 0x4F, 0x42, 0x09, 0x04, 0x13, 0x1E, 0x3D, 0x30, 0x27, 0x2A,
       0xB1, 0xBC, 0xAB, 0xA6, 0x85, 0x88, 0x9F, 0x92, 0xD9, 0xD4, 0xC3, 0xCE, 0xED, 0xE0, 0xF7, 0xFA,
       0xB7, 0xBA, 0xAD, 0xA0, 0x83, 0x8E, 0x99, 0x94, 0xDF, 0xD2, 0xC5, 0xC8, 0xEB, 0xE6, 0xF1, 0xFC,
       0x67, 0x6A, 0x7D, 0x70, 0x53, 0x5E, 0x49, 0x44, 0x0F, 0x02, 0x15, 0x18, 0x3B, 0x36, 0x21, 0x2C,
       0x0C, 0x01, 0x16, 0x1B, 0x38, 0x35, 0x22, 0x2F, 0x64, 0x69, 0x7E, 0x73, 0x50, 0x5D, 0x4A, 0x47,
       0xDC, 0xD1, 0xC6, 0xCB, 0xE8, 0xE5, 0xF2, 0xFF, 0xB4, 0xB9, 0xAE, 0xA3, 0x80, 0x8D, 0x9A, 0x97];

   var nineTimes = [
       0x00, 0x09, 0x12, 0x1B, 0x24, 0x2D, 0x36, 0x3F, 0x48, 0x41, 0x5A, 0x53, 0x6C, 0x65, 0x7E, 0x77,
       0x90, 0x99, 0x82, 0x8B, 0xB4, 0xBD, 0xA6, 0xAF, 0xD8, 0xD1, 0xCA, 0xC3, 0xFC, 0xF5, 0xEE, 0xE7,
       0x3B, 0x32, 0x29, 0x20, 0x1F, 0x16, 0x0D, 0x04, 0x73, 0x7A, 0x61, 0x68, 0x57, 0x5E, 0x45, 0x4C,
       0xAB, 0xA2, 0xB9, 0xB0, 0x8F, 0x86, 0x9D, 0x94, 0xE3, 0xEA, 0xF1, 0xF8, 0xC7, 0xCE, 0xD5, 0xDC,
       0x76, 0x7F, 0x64, 0x6D, 0x52, 0x5B, 0x40, 0x49, 0x3E, 0x37, 0x2C, 0x25, 0x1A, 0x13, 0x08, 0x01,
       0xE6, 0xEF, 0xF4, 0xFD, 0xC2, 0xCB, 0xD0, 0xD9, 0xAE, 0xA7, 0xBC, 0xB5, 0x8A, 0x83, 0x98, 0x91,
       0x4D, 0x44, 0x5F, 0x56, 0x69, 0x60, 0x7B, 0x72, 0x05, 0x0C, 0x17, 0x1E, 0x21, 0x28, 0x33, 0x3A,
       0xDD, 0xD4, 0xCF, 0xC6, 0xF9, 0xF0, 0xEB, 0xE2, 0x95, 0x9C, 0x87, 0x8E, 0xB1, 0xB8, 0xA3, 0xAA,
       0xEC, 0xE5, 0xFE, 0xF7, 0xC8, 0xC1, 0xDA, 0xD3, 0xA4, 0xAD, 0xB6, 0xBF, 0x80, 0x89, 0x92, 0x9B,
       0x7C, 0x75, 0x6E, 0x67, 0x58, 0x51, 0x4A, 0x43, 0x34, 0x3D, 0x26, 0x2F, 0x10, 0x19, 0x02, 0x0B,
       0xD7, 0xDE, 0xC5, 0xCC, 0xF3, 0xFA, 0xE1, 0xE8, 0x9F, 0x96, 0x8D, 0x84, 0xBB, 0xB2, 0xA9, 0xA0,
       0x47, 0x4E, 0x55, 0x5C, 0x63, 0x6A, 0x71, 0x78, 0x0F, 0x06, 0x1D, 0x14, 0x2B, 0x22, 0x39, 0x30,
       0x9A, 0x93, 0x88, 0x81, 0xBE, 0xB7, 0xAC, 0xA5, 0xD2, 0xDB, 0xC0, 0xC9, 0xF6, 0xFF, 0xE4, 0xED,
       0x0A, 0x03, 0x18, 0x11, 0x2E, 0x27, 0x3C, 0x35, 0x42, 0x4B, 0x50, 0x59, 0x66, 0x6F, 0x74, 0x7D,
       0xA1, 0xA8, 0xB3, 0xBA, 0x85, 0x8C, 0x97, 0x9E, 0xE9, 0xE0, 0xFB, 0xF2, 0xCD, 0xC4, 0xDF, 0xD6,
       0x31, 0x38, 0x23, 0x2A, 0x15, 0x1C, 0x07, 0x0E, 0x79, 0x70, 0x6B, 0x62, 0x5D, 0x54, 0x4F, 0x46];

 function checkSize(input, size){
     if (input.length == size) { return 1; }
     return 0;
 }

 function SubBytes(s) {
     var arr = new Array(16);
     for (var i=0; i<16; i++){ arr[i] = sbox[(s[i])]; }
     return arr;
  }

 function InvSubBytes(s) {
     var arr = new Array(16);
     for (var i=0; i<16; i++){ arr[i] = invsbox[s[i]]; }
     return arr;
  }

  function ShiftRows(s)    { return [s[0],s[5],s[10],s[15],s[4],s[9],s[14],s[3],s[8],s[13],s[2],s[7],s[12],s[1],s[6],s[11]]; }
  function InvShiftRows(s) { return [s[0],s[13],s[10],s[7],s[4],s[1],s[14],s[11],s[8],s[5],s[2],s[15],s[12],s[9],s[6],s[3]]; }

  function MixColumns(s) {
     var arr = new Array(16);
     var idx0, idx1, idx2, idx3;
     for (var i=0; i<4; i++){
		idx0 = 4 * i;
		idx1 = idx0 + 1;
		idx2 = idx0 + 2;
		idx3 = idx0 + 3;
        arr[idx0] =   twoTimes[s[idx0]] ^ threeTimes[s[idx1]] ^            s[idx2]  ^            s[idx3];
        arr[idx1] =            s[idx0]  ^   twoTimes[s[idx1]] ^ threeTimes[s[idx2]] ^            s[idx3];
        arr[idx2] =            s[idx0]  ^            s[idx1]  ^   twoTimes[s[idx2]] ^ threeTimes[s[idx3]];
        arr[idx3] = threeTimes[s[idx0]] ^            s[idx1]  ^            s[idx2]  ^   twoTimes[s[idx3]];
     }
     return arr;
   }

   function InvMixColumns(s) {
      var arr = new Array(16);
      var idx0, idx1, idx2, idx3;
      for (var i=0; i<4; i++){
         idx0 = 4 * i;
         idx1 = idx0 + 1;
         idx2 = idx0 + 2;
         idx3 = idx0 + 3;
         arr[idx0] = fourteenTimes[s[idx0]] ^   elevenTimes[s[idx1]] ^ thirteenTimes[s[idx2]] ^     nineTimes[s[idx3]];
         arr[idx1] =     nineTimes[s[idx0]] ^ fourteenTimes[s[idx1]] ^   elevenTimes[s[idx2]] ^ thirteenTimes[s[idx3]];
         arr[idx2] = thirteenTimes[s[idx0]] ^     nineTimes[s[idx1]] ^ fourteenTimes[s[idx2]] ^   elevenTimes[s[idx3]];
         arr[idx3] =   elevenTimes[s[idx0]] ^ thirteenTimes[s[idx1]] ^     nineTimes[s[idx2]] ^ fourteenTimes[s[idx3]];
      }
      return arr;
   }

   function AddRoundKey(s, k) {
      var arr = new Array(16);
      for (var i=0; i<4; i++) {
         arr[i]      = s[i]      ^ k[i];
         arr[4  + i] = s[4  + i] ^ k[4  + i];
         arr[8  + i] = s[8  + i] ^ k[8  + i];
         arr[12 + i] = s[12 + i] ^ k[12 + i];
      }
      return arr;
   }

   function KeyExpansion(key) {
      if (key.length == 16)      { var Nk = 4; var Nr = 10; } // 128bit Key  Nr = 10, 12, 14  amount of rounds
      else if (key.length == 24) { var Nk = 6; var Nr = 12; } // 192bit Key  Nk =  4   6,  8  key length in words (32 bits)
      else if (key.length == 32) { var Nk = 8; var Nr = 14; } // 256bit Key
      else                       { alert("AES-Error in KeyExpansion function:\nSize of Key is " + key.length + " long (should be 16, 24 or 32 Bytes)!\n"); return; }
      var rcon = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];
      var w     = new Array(4 * (Nr + 1));
      var temp  = new Array(4);
      var pos   = 0;
      var round = 1;                                                                 // Key expansion computation starts with round 1 (in round 0 the original key is copied as shown below)
      for (var i=0; i < 4 * Nk; i++){ w[i] = key[i]; }                               // Round 0: initialize the first Nk words of the expanded key with the original key
      for (var i=Nk; i<(4 * (Nr + 1)); i++) {                                        // Start key expansion right after the insertion of the original key and do the following
         for (var j=0; j<4; j++){ temp[j] = w[4 * (i - 1) + j]; }                    //   Copy ancestor word (32bit) into the temporary word "temp"
         if (pos == 0) {                                                             //   Each Nk'th word is transformed by the following extra steps
            temp    = SubWord(RotWord(temp));                                        //     + RotWord() + SubWord() are applied to the ancestor word
            temp[0] = temp[0] ^ rcon[round];                                         //     + xor with rcon[round]  Note that rcon does always modify the first byte only (others remain unchanged).
         }
         else if (Nk > 6 && (pos == 4)){ temp = SubWord(temp); }                     //   Special case "256-bit key": Apply SubWord() every 4th word
         for (var j=0; j<4; j++) { w[4 * i  + j] = w[4 * (i - Nk) + j] ^ temp[j]; }  //   In the end compute: w[i] xor w[i-1] xor w[i-Nk]
         pos++;
         if (pos == Nk) { pos = 0; round++; }                                        //   If position marker reaches the key size (in words), reset the position marker and increment the round counter.
      }
      return w;
   }
    
   function SubWord(input) {
      var arr = new Array(4);
      for (var i=0; i<4; i++){ arr[i] = sbox[input[i]]; }
      return arr;
   }

   function RotWord(input) {
      return [input[1],input[2],input[3],input[0]];
   }

   function AESEncryptExpandedKey(state, w) {
      if (w.length == 176)      { var Nr = 10; } // 128bit Key  Nr = 10, 12, 14  # rounds
      else if (w.length == 208) { var Nr = 12; } // 192bit Key
      else if (w.length == 240) { var Nr = 14; } // 256bit Key
      else                     { alert("AES-Error in AESEncryptExpandedKey function:\nSize of Expanded-Key is " + w.length + " long (should be 176, 208 or 240 Bytes)!\n"); return; }
      var k = new Array(16);
      for (var j=0; j<16; j++) { k[j] = w[j]; }
      state = AddRoundKey(state, k);
      for (var round = 0; round < Nr - 1; round++) {
         state = SubBytes(state);
         state = ShiftRows(state);
         state = MixColumns(state);
         for (var j=0; j<16; j++){ k[j] = w[16 * (round + 1) + j]; }
         state = AddRoundKey(state, k);
      }
      state = SubBytes(state);
      state = ShiftRows(state);
      for (var j=0; j<16; j++){ k[j] = w[16 * Nr + j]; }
      state = AddRoundKey(state, k);
      return state;
   }
   
   function AESDecryptExpandedKey(state, w)  {
      if (w.length == 176)      { var Nr = 10; } // 128bit Key  Nr = 10, 12, 14  # rounds
      else if (w.length == 208) { var Nr = 12; } // 192bit Key
      else if (w.length == 240) { var Nr = 14; } // 256bit Key
      else                     { alert("AES-Error in AESEncryptExpandedKey function:\nSize of Expanded-Key is " + w.length + " long (should be 176, 208 or 240 Bytes)!\n"); return; }
      var k = new Array(16);
      for (var j=0; j<16; j++) { k[j] = w[4 * (Nr * 4) + j]; }
      state = AddRoundKey(state, k);
      for (var round = (Nr - 1); round > 0; round--) {
         state = InvShiftRows(state);
         state = InvSubBytes(state);
         for (var j=0; j<16; j++) { k[j] = w[16 * (round) + j]; }
         state = AddRoundKey(state, k);
         state = InvMixColumns(state);
      }
      state = InvShiftRows(state);
      state = InvSubBytes(state);
      for (var j=0; j<16; j++) { k[j] = w[j]; }
      state = AddRoundKey(state, k);
      return state;
   }

   function AESEncrypt(plainbytearr, key) { return AESEncryptExpandedKey(plainbytearr, KeyExpansion(key)); } // SINGLE BLOCK (128bit) Encryption
   function AESDecrypt(plainbytearr, key) { return AESDecryptExpandedKey(plainbytearr, KeyExpansion(key)); } // SINGLE BLOCK (128bit) Decryption


// ------------ PUBLIC FUNCTIONS: YOU MAY USE THE FUNCTIONS BELOW IN YOUR JAVASCRIPT CODE --------------------------------------------------------------------------------------------------------------------------------------------

   function encryptCBC(m, k, iv) { // CBC-MODE   m...message (bytearray[n]), k...key (bytearray[16]), iv...initialvector (bytearray[16])   PKCS7-PADDING 
      var n = m.length;
      if (n == 0)                                                   { alert("AES-Error in encryptCBC function:\nSize of Plaintext is 0!\n");                                              return; }
      else if (iv.length != 16)                                     { alert("AES-Error in encryptCBC function:\nSize of Initial Vector is not 16 Bytes long!\n");                         return; }
      else if (k.length  != 16 && k.length != 24 && k.length != 32) { alert("AES-Error in encryptCBC function:\nSize of Key is " + k.length + " long (should be 16, 24 or 32 Bytes)!\n"); return; }
      else {
         var diff       = 16 - (n % 16);
         var size       = n + diff;
         var cblock     = new Array(size);
         var plainX128  = new Array(16);
         var cipher128  = new Array(16);

         var w = KeyExpansion(k);
         for (var i=n; i<size; i++) { m[i] = diff;                 }  // PKCS7-PADDING 
         for (var i=0; i<16;   i++) { plainX128[i] = m[i] ^ iv[i]; }  // First round: encrypt(m0 XOR iv,key)
         cipher128 = AESEncryptExpandedKey(plainX128, w);             // AESEncrypt (with existing expanded key - does not need to be recalculated!)
         for (var i=0; i<16; i++)   { cblock[i] = cipher128[i];    }  // Copying current cipher block to the output array

         var idx;
         for (var i=16; i<size; i+=16){                               // From round2 until the end
            for (var j=0; j<16; j++){
               idx = i + j;
               plainX128[j] = (m[idx] ^ cblock[idx - 16]);            // CBC-XOR-chain-linking of current plaintext with the ciphertext of the previous round
            }
            cipher128 = AESEncryptExpandedKey(plainX128, w);
            for (var j=0; j<16; j++){ cblock[i + j] = cipher128[j]; }
         }
         return cblock;
      }
   }

   function decryptCBC(c, k, iv) { // CBC-MODE   c...cipher (bytearray[n]), k...key (bytearray[16]), iv...initialvector (bytearray[16])
      var n = c.length;
      if (n == 0)                                                   { alert("AES-Error in decryptCBC function:\nSize of Ciphertext is 0!\n\n");                                                                 return; }
      else if (n % 16 != 0)                                         { alert("AES-Error in decryptCBC function:\nSize of Ciphertext is incorrect: " + (n * 8) + " bits\nRequired size: multiple of 16 bits.\n");         }
      else if (iv.length != 16)                                     { alert("AES-Error in decryptCBC function:\nSize of Initial Vector is not 16 Bytes long!\n");                                                       }
      else if (k.length  != 16 && k.length != 24 && k.length != 32) { alert("AES-Error in decryptCBC function:\nSize of Key is " + k.length + " long (should be 16, 24 or 32 Bytes)!\n");                               }
      else {
         var w          = KeyExpansion(k);
         var mblock     = new Array(n);
         var plain128   = new Array(16);
         var cipher128  = new Array(16);
         
         for (var j=0; j<16; j++) { cipher128[j] = c[j]; }              // 1st Rnd: decrypt(c,key) XOR iv
         plain128 = AESDecryptExpandedKey(cipher128, w);                // AESDecrypt (with existing expanded key - does not need to be recalculated!)
         for (var j=0; j<16; j++) { mblock[j] = plain128[j] ^ iv[j]; }  // Copying current plaintext block to the output array

         var index;
         for (var i=16; i<n; i += 16) {
            for (var j=0; j<16; j++) { cipher128[j] = c[i + j]; }
            plain128 = AESDecryptExpandedKey(cipher128, w);
            for (var j=0; j<16; j++) {
               index = i + j;
               mblock[index] = plain128[j] ^ c[index-16];
            }
         }
         var i    = mblock[n-1];  // Cutting off PKCS7 padding bytes
         var last = n-i;
         if  (i > 16 || last < 1 || last >= n) { alert("AES-Error in decryptCBC function:\nPadding is invalid!\n\nYou may have used an invalid ciphertext, a wrong key or a wrong padding scheme.\n"); return; }
         var m = new Array(last);
         for (var j=0; j<last; j++){ m[j] = mblock[j]; }
         return m;
      }   
   }   
   
   function encryptCTR(m, k, iv) { // COUNTER-MODE   m...message (bytearray[n]), k...key (bytearray[16]), iv...initialvector (bytearray[16])  RECOMMENDED ENCRYPTION-FUNCTION!
      var n = m.length;            //                                                                                                         Note that stream ciphers like CTR mode do not need padding bits.
      if (n == 0)                                                   { alert("AES-Error in encryptCTR function:\nSize of Plaintext is 0!\n");                                              return; }
      else if (iv.length != 16)                                     { alert("AES-Error in encryptCTR function:\nSize of Initial Vector is not 16 Bytes long!\n");                         return; }
      else if (k.length  != 16 && k.length != 24 && k.length != 32) { alert("AES-Error in encryptCTR function:\nSize of Key is " + k.length + " long (should be 16, 24 or 32 Bytes)!\n"); return; }
      else {
         var blockidx   = 0;
         var lastblock  = Math.ceil(n / 16) - 1;
         var lastidx    = (n % 16) || 16;
         var diff       = (16 - lastidx) % 16;
         var size       = n + diff;
         var c          = new Array(n);
         var cipher128  = new Array(16);
         
         var w = KeyExpansion(k);
         for (var i=0; i<size; i+=16){
            cipher128 = AESEncryptExpandedKey(iv, w);                            // Encrypt IV with AES and key k  Note that expanded key already existst - it does not need to be recalculated.
            if (blockidx == lastblock) {                                         // Last block may consist of less than 16 bytes
               for (var j=0; j<lastidx; j++) { c[i+j] = m[i+j] ^ cipher128[j]; } // XOR cipher output with plaintext (block length of 16 bytes or less)
            }
            else {
               for (var j=0; j<16; j++) { c[i+j] = m[i+j] ^ cipher128[j]; }      // XOR cipher output with plaintext (full block length of 16 bytes)
               iv[0] = (iv[0] + 1) & 0xff;                                       // Increment IV (Counter)
               if (iv[0] == 0) {                                                 // Handle carry-overs
                  iv[1] = (iv[1] + 1) & 0xff;
                  if (iv[1] == 0) {
                     iv[2] = (iv[2] + 1) & 0xff;
                     if (iv[2] == 0) {
                        iv[3] = (iv[3] + 1) & 0xff;
                     }
                  }
               }
            }
            blockidx++;
         }
         return c;
      }
   }
   
   function decryptCTR(c, k, iv) { // COUNTER-MODE   c...cipher (bytearray[n]), k...key (bytearray[16]), iv...initialvector (bytearray[16])  RECOMMENDED DECRYPTION-FUNCTION!
      var n = c.length;            //                                                                                                        Note that stream ciphers like CTR mode do not need padding bits.
      if (n == 0)                                                   { alert("AES-Error in encryptCTR function:\nSize of Plaintext is 0!\n");                                              return; }
      else if (iv.length != 16)                                     { alert("AES-Error in encryptCTR function:\nSize of Initial Vector is not 16 Bytes long!\n");                         return; }
      else if (k.length  != 16 && k.length != 24 && k.length != 32) { alert("AES-Error in encryptCTR function:\nSize of Key is " + k.length + " long (should be 16, 24 or 32 Bytes)!\n"); return; }
      else {
         var blockidx   = 0;
         var lastblock  = Math.ceil(n / 16) - 1;
         var lastidx    = (n % 16) || 16;
         var diff       = (16 - lastidx) % 16;
         var size       = n + diff;
         var m          = new Array(n);
         var cipher128  = new Array(16);
         
         var w = KeyExpansion(k);
         for (var i=0; i<size; i+=16){
            cipher128 = AESEncryptExpandedKey(iv, w);                            // Encrypt IV with AES and key k  Note that expanded key already existst - it does not need to be recalculated.
            if (blockidx == lastblock) {                                         // Last block may consist of less than 16 bytes
               for (var j=0; j<lastidx; j++) { m[i+j] = c[i+j] ^ cipher128[j]; } // XOR cipher output with ciphertext (block length of 16 bytes or less)
            }
            else {
               for (var j=0; j<16; j++) { m[i+j] = c[i+j] ^ cipher128[j]; }      // XOR cipher output with ciphertext (full block length of 16 bytes)
               iv[0] = (iv[0] + 1) & 0xff;                                       // Increment IV (Counter)
               if (iv[0] == 0) {                                                 // Handle carry-overs
                  iv[1] = (iv[1] + 1) & 0xff;
                  if (iv[1] == 0) {
                     iv[2] = (iv[2] + 1) & 0xff;
                     if (iv[2] == 0) {
                        iv[3] = (iv[3] + 1) & 0xff;
                     }
                  }
               }
            }
            blockidx++;
         }
         return m;
      }
   }
