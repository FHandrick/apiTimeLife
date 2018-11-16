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

method(3,"F2m(int m, int k, BigInteger x)","org.bouncycastle.math.ec.ECFieldElement.F2m").
method(3,"getPreComp()","org.bouncycastle.math.ec.FixedPointPreCompInfo").
method(3,"setPreComp(ECPoint[] preComp)","org.bouncycastle.math.ec.FixedPointPreCompInfo").
method(3,"getWidthForCombSize(int combSize)","org.bouncycastle.math.ec.FixedPointCombMultiplier").
method(3,"getN()","org.bouncycastle.math.ec.ECCurve.F2m").
method(3,"getH()","org.bouncycastle.math.ec.ECCurve.F2m").
method(3,"getX()","org.bouncycastle.math.ec.ECPoint").
method(3,"getY()","org.bouncycastle.math.ec.ECPoint").
method(3,"Fp(ECCurve curve, ECFieldElement x, ECFieldElement y)","org.bouncycastle.math.ec.ECPoint.Fp").
method(3,"F2m(ECCurve curve, ECFieldElement x, ECFieldElement y)","org.bouncycastle.math.ec.ECPoint.F2m").
method(3,"precompute(ECPoint p, int minWidth)","org.bouncycastle.math.ec.FixedPointUtil").
method(9,"Fp(BigInteger q, BigInteger r, BigInteger x)","org.bouncycastle.math.ec.ECCurve.Fp").
method(2,"setPreCompInfo(ECPoint, String, PreCompInfo)","precompute(ECPoint, String, PreCompCallback)","org.bouncycastle.math.ec.ECCurve").
method(2,"satisfiesCofactor()","satisfiesOrder()","org.bouncycastle.math.ec.ECPoint").
method(9,"Fp(BigInteger q, BigInteger r, BigInteger x)","org.bouncycastle.math.ec.ECCurve.Fp").
method(3,"cnegate(int negate, int[] x, int[] z)","org.bouncycastle.math.ec.rfc7748.X25519Field").
method(3,"generatePublicKey(byte[] ctx, byte[] sk, int skOff, byte[] pk, int pkOff)","org.bouncycastle.math.ec.rfc8032.Ed448").
method(3,"sign(byte[] ctx, byte[] sk, int skOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)","org.bouncycastle.math.ec.rfc8032.Ed448").
method(3,"sign(byte[] ctx, byte[] sk, int skOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen, byte[] sig, int sigOff)","org.bouncycastle.math.ec.rfc8032.Ed448").
method(3,"verify(byte[] ctx, byte[] sig, int sigOff, byte[] pk, int pkOff, byte[] m, int mOff, int mLen)","org.bouncycastle.math.ec.rfc8032.Ed448").
method(8,"getUserAttributes()","org.bouncycastle.openpgp.PGPSecretKey").
method(8,"getUserIDs()","org.bouncycastle.openpgp.PGPSecretKey").
method(9,"KeyInformation(byte[] fingerprint, long offsetToKeyID, int keyFlags, byte[] filler, byte[] keyID)","org.bouncycastle.gpg.keybox.KeyInformation").
method(9,"getInstance(Object src, int expectedSize, int base)","org.bouncycastle.gpg.keybox.KeyInformation").
method(9,"verifyDigest(int base, long length, KeyBoxByteBuffer buffer)","org.bouncycastle.gpg.keybox.KeyBlob").
method(9,"getInstance(Object src, int base)","org.bouncycastle.gpg.keybox.UserID").
method(9,"parseContent(int base, long length, BlobType type, int version, KeyBoxByteBuffer buffer)","org.bouncycastle.gpg.keybox.FirstBlob").
method(3,"getLength()","org.bouncycastle.gpg.keybox.Blob").
method(3,"getOffsetToKeyID()","org.bouncycastle.gpg.keybox.KeyInformation").
method(3,"KeyBlob(int base, long length, BlobType type, int version, int blobFlags, long keyBlockOffset, long keyBlockLength, int keyNumber, int additionalKeyInfoSize, List<KeyInformation> keyInformation, int sizeOfSerialNumber, byte[] serialNumber, int numberOfUserIDs, int sizeOfUserIdInformation, List<UserID> userIds, int numberOfSignatures, int sizeOfSignatureInfo, List<Long> expirationTime, int assignedOwnerTrust, int allValidity, long recheckAfter, long newestTimestamp, long blobCreatedAt, long sizeOfReservedSpace, byte[] keyBytes, byte[] reserveBytes, byte[] sha1Checksum)","org.bouncycastle.gpg.keybox.KeyBlob").
method(3,"getKeyBlockOffset()","org.bouncycastle.gpg.keybox.KeyBlob").
method(3,"getKeyBlockLength()","org.bouncycastle.gpg.keybox.KeyBlob").
method(3,"getAdditionalKeyInfoSize()","org.bouncycastle.gpg.keybox.KeyBlob").
method(3,"getSizeOfSerialNumber()","org.bouncycastle.gpg.keybox.KeyBlob").
method(3,"getSizeOfUserIdInformation()","org.bouncycastle.gpg.keybox.KeyBlob").
method(3,"getSizeOfSignatureInfo()","org.bouncycastle.gpg.keybox.KeyBlob").
method(3,"getSizeOfReservedSpace()","org.bouncycastle.gpg.keybox.KeyBlob").
method(7,"getEncodedCertificate()","org.bouncycastle.gpg.keybox.CertificateBlob").
method(7,"engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)","org.bouncycastle.jcajce.provider.asymmetric.elgamal.CipherSpi").
method(7,"engineGetEncoded()","org.bouncycastle.jcajce.provider.symmetric.IDEA.AlgParams").
method(7,"engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(7,"engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(7,"engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(7,"engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)","org.bouncycastle.jcajce.provider.asymmetric.elgamal.CipherSpi").
method(7,"engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(3,"isProbablePrime(BigInteger x, int iterations)","org.bouncycastle.crypto.generators.RSAKeyPairGenerator").
method(3,"isProbablePrime(BigInteger x)","org.bouncycastle.crypto.generators.RSAKeyPairGenerator").
method(7,"engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(3,"deserialize(byte[] data)","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(3,"safeReadFullRecord(byte[] record)","org.bouncycastle.tls.TlsProtocol").
method(7,"handleFailure()","org.bouncycastle.tls.TlsProtocol").


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
