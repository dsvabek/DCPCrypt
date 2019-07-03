unit DCPEncrypt;    

	// HMAC (Hash-based Message Authentication Code)
	// PBKDF1/PBKDF2 (Password-Based Key Derivation Function 1/2)
	// adapted from code found at http://keit.co/p/dcpcrypt-hmac-rfc2104/

interface

	uses
      DCPcrypt2, DCPsha1, DCPmd5, DCPsha512, DCPhaval,
      DCPmd4, DCPtiger, DCPripemd128, DCPripemd160, DCPsha256, Math;	

	function CalcHMAC(message, key: string; hash: TDCP_hashclass): string;			
	function PBKDF1(pass, salt: ansistring; count: Integer; hash: TDCP_hashclass): ansistring;			
	function PBKDF2(pass, salt: ansistring; count, kLen: Integer; hash: TDCP_hashclass): ansistring;	
	
implementation
    function RPad(x: string; c: Char; s: Integer): string;
      var
        i: Integer;
      begin
        Result := x;
        if Length(x) < s then
          for i := 1 to s-Length(x) do
            Result := Result + c;
      end;

      function XorBlock(s, x: ansistring): ansistring; inline;
      var
        i: Integer;
      begin
        SetLength(Result, Length(s));
        for i := 1 to Length(s) do
          Result[i] := Char(Byte(s[i]) xor Byte(x[i]));
      end;

      function CalcDigest(text: string; dig: TDCP_hashclass): string;
      var
        x: TDCP_hash;
      begin
        x := dig.Create(nil);
        try
          x.Init;
          x.UpdateStr(text);
          SetLength(Result, x.GetHashSize div 8);
          x.Final(Result[1]);
        finally
          x.Free;
        end;
      end;

      function CalcHMAC(message, key: string; hash: TDCP_hashclass): string;
      const
        blocksize_big = 128;
        blocksize_small = 64;
      var
        blocksize : Integer;
      begin

        // https://en.wikipedia.org/wiki/Comparison_of_cryptographic_hash_functions

        if (hash = TDCP_sha384) or (hash = TDCP_sha512) or
           (hash = TDCP_sha512base) or (hash = TDCP_haval)
        then begin
          blocksize := blocksize_big;
        end else
        if (hash = TDCP_sha256) or (hash = TDCP_sha1) or
           (hash = TDCP_ripemd128) or (hash = TDCP_ripemd160) or
           (hash = TDCP_tiger) or (hash = TDCP_md4) or
           (hash = TDCP_md5)
        then begin
          blocksize := blocksize_small;
        end else
        begin
          blocksize := blocksize_small;
        end;  

        // Definition RFC 2104
        if Length(key) > blocksize then
          key := CalcDigest(key, hash)
        else
          key := RPad(key, #0, blocksize);

        Result := CalcDigest(XorBlock(key, RPad('', #$36, blocksize)) + message, hash);
        Result := CalcDigest(XorBlock(key, RPad('', #$5c, blocksize)) + result, hash);
      end;

      function PBKDF1(pass, salt: ansistring; count: Integer; hash: TDCP_hashclass): ansistring;
      var
        i: Integer;
      begin
        Result := pass+salt;
        for i := 0 to count-1 do
          Result := CalcDigest(Result, hash);
      end;

      function PBKDF2(pass, salt: ansistring; count, kLen: Integer; hash: TDCP_hashclass): ansistring;

        function IntX(i: Integer): ansistring; inline;
        begin
          Result := Char(i shr 24) + Char(i shr 16) + Char(i shr 8) + Char(i);
        end;

      var
        D, I, J: Integer;
        T, F, U: ansistring;
      begin
        T := '';
        D := Ceil(kLen / (hash.GetHashSize div 8));
        for i := 1 to D do
        begin
          F := CalcHMAC(salt + IntX(i), pass, hash);
          U := F;
          for j := 2 to count do
          begin
            U := CalcHMAC(U, pass, hash);
            F := XorBlock(F, U);
          end;
          T := T + F;
        end;
        Result := Copy(T, 1, kLen);
      end;
