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

method(8,"getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlg)","org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator").
method(3,"GF2nPolynomialField(int deg)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomialField").
method(3,"GF2nPolynomialField(int deg, boolean file)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomialField").
method(3,"GF2nPolynomialField(int deg, GF2Polynomial polynomial)","org.bouncycastle.pqc.math.linearalgebra.GF2nPolynomialField").
method(3,"GF2nONBElement(GF2nONBField gf2n, Random rand)","org.bouncycastle.pqc.math.linearalgebra.GF2nONBElement").
method(3,"GF2nONBField(int deg)","org.bouncycastle.pqc.math.linearalgebra.GF2nONBField").
method(3,"chooseRandomPrime(int bitlength, BigInteger e)","org.bouncycastle.crypto.generators.RSAKeyPairGenerator").
method(8,"getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlgorithm)","org.bouncycastle.cms.KeyAgreeRecipientInfoGenerator").
method(8,"getUserKeyingMaterial(AlgorithmIdentifier keyAgreeAlg)","org.bouncycastle.cms.jcajce.JceKeyAgreeRecipientInfoGenerator").
method(7,"engineGenerateSecret(String algorithm)","org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi").
method(3,"init(boolean encrypting, CipherParameters params)","org.bouncycastle.crypto.engines.SerpentEngine").
method(3,"getAlgorithmName()","org.bouncycastle.crypto.engines.SerpentEngine").
method(3,"getBlockSize()","org.bouncycastle.crypto.engines.SerpentEngine").
method(3,"processBlock(byte[] in, int inOff, byte[] out, int outOff)","org.bouncycastle.crypto.engines.SerpentEngine").
method(3,"reset()","org.bouncycastle.crypto.engines.SerpentEngine").
method(7,"PKCS10CertificationRequest(byte[] bytes)","org.bouncycastle.jce.PKCS10CertificationRequest").
method(7,"getEncoded()","org.bouncycastle.jce.PKCS10CertificationRequest").
method(3,"getBytes()","org.bouncycastle.asn1.DERBitString").
method(3,"getBytes()","org.bouncycastle.asn1.DLBitString").
method(8,"getInstance(Object obj)","org.bouncycastle.asn1.DLBitString").
method(8,"getInstance(ASN1TaggedObject obj, boolean explicit)","org.bouncycastle.asn1.DLBitString").
method(7,"engineGenerateSecret(String algorithm)","org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi").
method(7,"applicationDataAvailable()","org.bouncycastle.crypto.tls.TlsProtocol").


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
