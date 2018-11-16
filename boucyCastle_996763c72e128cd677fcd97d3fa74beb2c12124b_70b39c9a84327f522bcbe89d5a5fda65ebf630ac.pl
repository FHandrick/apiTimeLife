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

method(2,"getMD5()","createMD5()","org.bouncycastle.crypto.util.DigestFactory").
method(2,"getSHA1()","createSHA1()","org.bouncycastle.crypto.util.DigestFactory").
method(2,"getSHA224()","createSHA224()","org.bouncycastle.crypto.util.DigestFactory").
method(2,"getSHA256()","createSHA256()","org.bouncycastle.crypto.util.DigestFactory").
method(2,"getSHA384()","createSHA384()","org.bouncycastle.crypto.util.DigestFactory").
method(2,"getSHA512()","createSHA512()","org.bouncycastle.crypto.util.DigestFactory").
method(2,"getSHA512_224()","createSHA512_224()","org.bouncycastle.crypto.util.DigestFactory").
method(2,"getSHA512_256()","createSHA512_256()","org.bouncycastle.crypto.util.DigestFactory").
method(7,"update(byte b)","org.bouncycastle.openpgp.PGPSignature").
method(7,"update(byte[] bytes)","org.bouncycastle.openpgp.PGPSignature").
method(7,"update(byte[] bytes, int off, int length)","org.bouncycastle.openpgp.PGPSignature").
method(7,"engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(3,"safeDecryptPreMasterSecret(TlsCryptoParameters cryptoParams, RSAPrivateKey rsaServerPrivateKey, byte[] encryptedPreMasterSecret)","org.bouncycastle.tls.crypto.impl.jcajce.JceDefaultTlsCredentialedDecryptor").
method(3,"BouncyCastleJsseProvider(boolean fipsMode, TlsCryptoProvider tlsCryptoProvider)","org.bouncycastle.jsse.provider.BouncyCastleJsseProvider").
method(2,"writeData(byte[], int, int)","writeApplicationData(byte[], int, int)","org.bouncycastle.tls.TlsProtocol").
method(3,"offerOutput(byte[] buffer, int offset, int length)","org.bouncycastle.tls.TlsProtocol").
method(3,"generateRandomSecret(int length)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"generateRandomSecret(int length)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(7,"getCipherType(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(7,"getEncryptionAlgorithm(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(7,"getKeyExchangeAlgorithm(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(7,"getMACAlgorithm(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(3,"JceTlsECDH(JcaTlsECDomain domain)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsECDH").
method(3,"BouncyCastleJsseProvider(boolean fipsMode, TlsCrypto tlsCrypto)","org.bouncycastle.jsse.provider.BouncyCastleJsseProvider").
method(2,"createBlockCipherWithImplicitIV(String, String, int, boolean)","createBlockCipherWithCBCImplicitIV(String, String, int, boolean)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(2,"createCipherSuite(TlsCryptoParameters, int, int)","createCipher(TlsCryptoParameters, int, int)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"createCipherSuite(TlsCryptoParameters cryptoParams, int encryptionAlgorithm, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.AbstractTlsCrypto").
method(2,"createCipherSuite(TlsCryptoParameters, int, int)","createCipher(TlsCryptoParameters, int, int)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(2,"createCipherSuite(TlsCryptoParameters, int, int)","createCipher(TlsCryptoParameters, int, int)","org.bouncycastle.tls.crypto.impl.AbstractTlsSecret").
method(8,"getCipher()","org.bouncycastle.tls.AbstractTlsClient").
method(8,"createAESCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createCamelliaCipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createChaCha20Poly1305(TlsCryptoParameters cryptoParams)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createCipher_AES_CCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createCipher_AES_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createCipher_AES_OCB(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createCipher_Camellia_GCM(TlsCryptoParameters cryptoParams, int cipherKeySize, int macSize)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createDESedeCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createRC4Cipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createSEEDCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(8,"createAEADCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(8,"createBlockCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(8,"createBlockCipherWithImplicitIV(String cipherName, String algorithm, int keySize, boolean isEncrypting)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(8,"createStreamCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(8,"createNullCipher(TlsCryptoParameters cryptoParams, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(8,"getCipher()","org.bouncycastle.tls.AbstractTlsServer").
method(3,"IESParameterSpec(byte[] derivation, byte[] encoding, int macKeySize, int cipherKeySize)","org.bouncycastle.jce.spec.IESParameterSpec").
method(3,"ECIESwithCipher(BlockCipher cipher)","org.bouncycastle.jcajce.provider.asymmetric.ec.IESCipher.ECIESwithCipher").
method(3,"guessParameterSpec(BufferedBlockCipher iesBlockCipher)","org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil").
method(3,"IESCipher(OldIESEngine engine)","org.bouncycastle.jcajce.provider.asymmetric.dh.IESCipher").
method(7,"engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(7,"engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random)","org.bouncycastle.jcajce.provider.asymmetric.rsa.CipherSpi").
method(3,"BCDSTU4145PublicKey(org.bouncycastle.jce.spec.ECPublicKeySpec spec)","org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PublicKey").
method(3,"BCDSTU4145PublicKey(ECPublicKey key)","org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PublicKey").
method(3,"engineGetQ()","org.bouncycastle.jcajce.provider.asymmetric.dstu.BCDSTU4145PublicKey").
method(3,"BCECGOST3410PublicKey(org.bouncycastle.jce.spec.ECPublicKeySpec spec)","org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey").
method(3,"engineGetQ()","org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey").
method(3,"engineGetQ()","org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey").
method(3,"engineGetQ()","org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey").
method(3,"getOrderBitLength(BigInteger order, BigInteger privateValue)","org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil").
method(3,"engineGetQ()","org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey").


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
