/* facts */

/* metohod(1...  - Move Method */
/* metohod(2...  - Rename Method */
/* metohod(3...  - Remove Method */
/* metohod(4...  - Push Down Method */
/* metohod(5...  - Inline Method */
/* metohod(6...  - Change in Parameter List Method */
/* metohod(7...  - Change in Exception LIst Method*/
/* metohod(8...  - Change in Return TYpe Method */
/* metohod(9...  - Lost Visibility Method */
/* metohod(10...  - Add Final Modifier */
/* metohod(11...  - Remove Static Modifier */

method(8,"getCause()","org.bouncycastle.cert.path.CertPathValidationResult").
method(3,"KeyAgreementSpi(String kaAlgorithm, ECDHCEphemeralAgreement agreement, DerivationFunction kdf)","org.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi").
method(3,"main(String[] args)","org.bouncycastle.jcajce.provider.keystore.pkcs12.PKCS12KeyStoreSpi").
method(3,"GOST3412ParametersWithIV(byte[] iv, CipherParameters parameters, int s, int m)","org.bouncycastle.crypto.params.GOST3412ParametersWithIV").
method(3,"getS()","org.bouncycastle.crypto.params.GOST3412ParametersWithIV").
method(3,"getDHParameters()","org.bouncycastle.tls.AbstractTlsServer").
method(3,"isSelectableCipherSuite(int cipherSuite, int availCurveBits, Vector sigAlgs)","org.bouncycastle.tls.AbstractTlsServer").
method(7,"selectDHConfig()","org.bouncycastle.tls.AbstractTlsServer").
method(9,"Fp(BigInteger q, BigInteger r, BigInteger x)","org.bouncycastle.math.ec.ECCurve.Fp").
method(2,"safeCheckRecordHeader(byte[])","safePreviewRecordHeader(byte[])","org.bouncycastle.tls.TlsProtocol").
method(3,"G3412CTRBlockCipher(BlockCipher cipher, int s)","org.bouncycastle.crypto.modes.G3412CTRBlockCipher").
method(3,"G3412CFBBlockCipher(BlockCipher cipher, int s, int m)","org.bouncycastle.crypto.modes.G3412CFBBlockCipher").
method(3,"calculateByte(byte b)","org.bouncycastle.crypto.modes.G3412CFBBlockCipher").
method(3,"validateCertificateRequest(CertificateRequest certificateRequest)","org.bouncycastle.tls.TlsECDHKeyExchange").
method(3,"validateCertificateRequest(CertificateRequest certificateRequest)","org.bouncycastle.tls.TlsDHKeyExchange").
method(3,"validateCertificateRequest(CertificateRequest certificateRequest)","org.bouncycastle.tls.TlsPSKKeyExchange").
method(3,"validateCertificateRequest(CertificateRequest certificateRequest)","org.bouncycastle.tls.TlsRSAKeyExchange").
method(3,"validateCertificateRequest(CertificateRequest certificateRequest)","org.bouncycastle.tls.TlsSRPKeyExchange").
method(3,"validateCertificateRequest(CertificateRequest certificateRequest)","org.bouncycastle.tls.TlsDHEKeyExchange").
method(3,"validateCertificateRequest(CertificateRequest certificateRequest)","org.bouncycastle.tls.TlsECDHEKeyExchange").
method(2,"double1x(long[], long[])","multiplyX(long[], long[])","org.bouncycastle.crypto.modes.kgcm.KGCMUtil_128").
method(2,"double8x(long[], long[])","multiplyX8(long[], long[])","org.bouncycastle.crypto.modes.kgcm.KGCMUtil_128").
method(2,"double1x(long[], long[])","multiplyX(long[], long[])","org.bouncycastle.crypto.modes.kgcm.KGCMUtil_256").
method(2,"double8x(long[], long[])","multiplyX8(long[], long[])","org.bouncycastle.crypto.modes.kgcm.KGCMUtil_256").
method(2,"double1x(long[], long[])","multiplyX(long[], long[])","org.bouncycastle.crypto.modes.kgcm.KGCMUtil_512").
method(2,"double8x(long[], long[])","multiplyX8(long[], long[])","org.bouncycastle.crypto.modes.kgcm.KGCMUtil_512").
method(3,"getFieldSize()","org.bouncycastle.crypto.agreement.SM2KeyExchange").
method(7,"add(GF2nPolynomial b)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomial").
method(7,"scalarMultiply(GF2nElement s)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomial").
method(7,"multiply(GF2nPolynomial b)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomial").
method(7,"multiplyAndReduce(GF2nPolynomial b, GF2nPolynomial g)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomial").
method(7,"divide(GF2nPolynomial b)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomial").
method(7,"gcd(GF2nPolynomial g)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomial").
method(7,"subtract(GFElement minuend)","org.bouncycastle.pqc.math.linearalgebra.GF2nElement").
method(7,"convert(GF2nField basis)","org.bouncycastle.pqc.math.linearalgebra.GF2nElement").
method(3,"generateSignature(byte[] message)","org.bouncycastle.crypto.signers.SM2Signer").
method(3,"verifySignature(byte[] message, BigInteger r, BigInteger s)","org.bouncycastle.crypto.signers.SM2Signer").


method_move_count(Y):-findall(X,method(1,A,B,C),L),length(L,Y).
method_rename_count(Y):-findall(X,method(2,A,B,C),L),length(L,Y).
method_remove_count(Y):-findall(X,method(3,A,B),L),length(L,Y).
method_inline_count(Y):-findall(X,method(5,A,B),L),length(L,Y).
method_change_exception_list_count(Y):-findall(X,method(7,A,B),L),length(L,Y).
method_change_return_type_count(Y):-findall(X,method(8,A,B),L),length(L,Y).
method_lost_visibility_count(Y):-findall(X,method(9,A,B),L),length(L,Y).
method_add_modifier_final_count(Y):-findall(X,method(10,A,B),L),length(L,Y).
method_remove_modifier_static_count(Y):-findall(X,method(11,A,B),L),length(L,Y).


all_method_change(A,B,C,D,E,F,G,H,I):-method_move_count(A),method_rename_count(B),method_remove_count(C),
method_inline_count(D),method_change_exception_list_count(E),method_change_return_type_count(F),method_lost_visibility_count(G),
method_add_modifier_final_count(H),method_remove_modifier_static_count(I).
