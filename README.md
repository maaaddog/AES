# AES
A very simple to use javascript code of the Advanced Encryption Standard (AES)
Author: Dr. Franz Kollmann

The following javascript code can be freely used.
The code is based on the original AES/Rijndael specification of the NIST.
Some improvements (e.g. predefined array values instead of calculations) are included to achieve better performance results.
Although the code was created with care, no guarantee/warranty of flawlessness and correctness will be given.

USAGE
  ENCRYPTION: Use encryptCTR(m, k, iv) or encryptCBC(m, k, iv) to encrypt message m with key k and initial vector iv   where m, k, iv represent byte arrays (convert your data to byte array accordingly)
  DECRYPTION: Use decryptCTR(c, k, iv) or decryptCBC(c, k, iv) to decrypt cipher  c with key k and initial vector iv   where c, k, iv represent byte arrays (convert your data to byte array accordingly)
