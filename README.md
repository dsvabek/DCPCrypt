# DCPEncrypt
For HMAC, PBKDF1, PBKDF2

*  HMAC (Hash-based Message Authentication Code)
*  PBKDF1/PBKDF2 (Password-Based Key Derivation Function 1/2)
*  adapted from code found at http://keit.co/p/dcpcrypt-hmac-rfc2104/
*  using information from https://en.wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions

## Improvements

* Corrected implementation of CalcHMAC used by PBKDF2 
* added support in HMAC and PBKDF2 for SHA384, SHA512 and haval
