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

method(7,"generatePublic(SubjectPublicKeyInfo pki)","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi").
method(7,"generatePrivate(PrivateKeyInfo pki)","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceCCA2KeyFactorySpi").
method(3,"toString()","org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePrivateKey").
method(3,"toString()","org.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey").
method(7,"generatePublic(SubjectPublicKeyInfo pki)","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKeyFactorySpi").
method(7,"generatePrivate(PrivateKeyInfo pki)","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKeyFactorySpi").
method(9,"workingKeyExpandKT(long[] workingKey, long[] tempKeys)","org.bouncycastle.crypto.engines.DSTU7624Engine").
method(9,"workingKeyExpandEven(long[] workingKey, long[] tempKey)","org.bouncycastle.crypto.engines.DSTU7624Engine").
method(9,"workingKeyExpandOdd()","org.bouncycastle.crypto.engines.DSTU7624Engine").
method(3,"createStreamCipher(String cipherName, String algorithm, int keySize, boolean isEncrypting)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(3,"createMAC(String macName)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(3,"createRC4Cipher(TlsCryptoParameters cryptoParams, int cipherKeySize, int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"init(byte[] iv)","org.bouncycastle.tls.crypto.impl.jcajce.JceStreamCipherImpl").
method(3,"setKey(byte[] key)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto.AeadOperator").
method(3,"setKey(byte[] key)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsMAC").
method(3,"setKey(byte[] key)","org.bouncycastle.tls.crypto.impl.jcajce.JceBlockCipherWithCBCImplicitIVImpl").
method(3,"init(byte[] iv)","org.bouncycastle.tls.crypto.impl.jcajce.JceBlockCipherWithCBCImplicitIVImpl").
method(3,"setKey(byte[] key)","org.bouncycastle.tls.crypto.impl.jcajce.JceAEADCipherImpl").
method(3,"setKey(byte[] key)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsHMAC").
method(3,"setKey(byte[] key)","org.bouncycastle.tls.crypto.impl.jcajce.JceStreamCipherImpl").
method(3,"setKey(byte[] key)","org.bouncycastle.tls.crypto.impl.jcajce.JceBlockCipherImpl").
method(3,"init(byte[] iv)","org.bouncycastle.tls.crypto.impl.jcajce.JceBlockCipherImpl").
method(3,"createPRFHash(int prfAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"hmacHash(Digest digest, byte[] secret, byte[] seed, byte[] output)","org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret").
method(3,"prf_1_2(Digest prfDigest, byte[] secret, byte[] labelSeed, int length)","org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret").
method(3,"hmacHash(String digestName, byte[] secret, byte[] seed, byte[] output)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret").
method(3,"prf_1_2(String prfDigest, byte[] secret, byte[] labelSeed, int length)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret").
method(3,"SimulatedTlsSRPIdentityManager(SRP6Group group, TlsSRP6VerifierGenerator verifierGenerator, TlsHMAC mac)","org.bouncycastle.tls.SimulatedTlsSRPIdentityManager").
method(2,"calculateECDHAgreement(ECPublicKeyParameters, ECPrivateKeyParameters)","calculateBasicAgreement(ECPrivateKeyParameters, ECPublicKeyParameters)","org.bouncycastle.tls.crypto.impl.bc.BcTlsECDomain").
method(1,"getCrypto()","org-bouncycastle-tls-crypto-impl-bc-bctlsecdomain,org.bouncycastle.jsse.provider.ProvSSLSessionContext").
method(2,"calculateDHAgreement(DHPublicKeyParameters, DHPrivateKeyParameters)","calculateBasicAgreement(DHPrivateKeyParameters, DHPublicKeyParameters)","org.bouncycastle.tls.crypto.impl.bc.BcTlsDHDomain").
method(1,"getCrypto()","org-bouncycastle-tls-crypto-impl-bc-bctlsdhdomain,org.bouncycastle.jsse.provider.ProvSSLSessionContext").
method(3,"calculateECDHAgreement(ECPublicKey publicKey, ECPrivateKey privateKey)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsECDomain").
method(1,"getCrypto()","org-bouncycastle-tls-crypto-impl-jcajce-jcetlsecdomain,org.bouncycastle.jsse.provider.ProvSSLSessionContext").
method(3,"convert(TlsCertificate certificate, JcaJceHelper helper)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate").
method(3,"JcaTlsCertificate(byte[] encoding, JcaJceHelper helper)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCertificate").
method(3,"calculateDHAgreement(DHPublicKey publicKey, DHPrivateKey privateKey)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsDHDomain").
method(1,"getCrypto()","org-bouncycastle-tls-crypto-impl-jcajce-jcetlsdhdomain,org.bouncycastle.jsse.provider.ProvSSLSessionContext").
method(7,"generateKeyPair()","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsDHDomain").
method(11,"decodeParameter(byte[] encoding)","org.bouncycastle.tls.crypto.impl.bc.BcTlsDHDomain").
method(3,"createHash(final SignatureAndHashAlgorithm signatureAndHashAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"createHMACDigest(int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"BcTlsDSASigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)","org.bouncycastle.tls.crypto.impl.bc.BcTlsDSASigner").
method(3,"BcTlsRSAVerifier(RSAKeyParameters pubKeyRSA)","org.bouncycastle.tls.crypto.impl.bc.BcTlsRSAVerifier").
method(3,"getStreamSigner(SignatureAndHashAlgorithm algorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsDSSSigner").
method(3,"BcTlsRSASigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)","org.bouncycastle.tls.crypto.impl.bc.BcTlsRSASigner").
method(3,"getStreamSigner(SignatureAndHashAlgorithm algorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsRSASigner").
method(3,"BcTlsECDSASigner(BcTlsCrypto crypto, AsymmetricKeyParameter privateKey)","org.bouncycastle.tls.crypto.impl.bc.BcTlsECDSASigner").
method(3,"createHash(final SignatureAndHashAlgorithm signatureAndHashAlgorithm)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(7,"createHMAC(int macAlgorithm)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(7,"createHMAC(String hmacName)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(3,"addSupportedEllipticCurvesExtension(Hashtable extensions, int[] namedCurves)","org.bouncycastle.tls.TlsECCUtils").
method(3,"getSupportedEllipticCurvesExtension(Hashtable extensions)","org.bouncycastle.tls.TlsECCUtils").
method(3,"createSupportedEllipticCurvesExtension(int[] namedCurves)","org.bouncycastle.tls.TlsECCUtils").
method(3,"readSupportedEllipticCurvesExtension(byte[] extensionData)","org.bouncycastle.tls.TlsECCUtils").
method(3,"hasNamedCurve(int curveID)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"getParameters(TlsECConfig ecConfig)","org.bouncycastle.tls.crypto.impl.bc.BcTlsECDomain").
method(2,"getParametersForNamedCurve(int)","getDomainParameters(int)","org.bouncycastle.tls.crypto.impl.bc.BcTlsECDomain").
method(3,"hasNamedCurve(int curveID)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(3,"getNamedCurve()","org.bouncycastle.tls.crypto.TlsECConfig").
method(3,"setNamedCurve(int namedCurve)","org.bouncycastle.tls.crypto.TlsECConfig").
method(2,"containsDHCipherSuites(int[])","containsDHECipherSuites(int[])","org.bouncycastle.tls.TlsDHUtils").
method(2,"isDHCipherSuite(int)","isDHECipherSuite(int)","org.bouncycastle.tls.TlsDHUtils").
method(2,"isChar2(int)","isChar2Curve(int)","org.bouncycastle.tls.NamedGroup").
method(2,"isPrime(int)","isPrimeCurve(int)","org.bouncycastle.tls.NamedGroup").
method(3,"DefaultTlsECConfigVerifier(int minimumCurveBits, int[] namedCurves)","org.bouncycastle.tls.DefaultTlsECConfigVerifier").
method(3,"validatePubKeyDH(DHPublicKeyParameters pubKeyDH)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate").
method(3,"validateDHPublicValues(BigInteger y, BigInteger p)","org.bouncycastle.tls.TlsDHUtils").
method(3,"getExplicitPG()","org.bouncycastle.tls.crypto.TlsDHConfig").
method(3,"setExplicitPG(BigInteger[] explicitPG)","org.bouncycastle.tls.crypto.TlsDHConfig").
method(3,"selectDHConfig(DHGroup dhGroup)","org.bouncycastle.tls.TlsDHUtils").
method(3,"areGroupsEqual(TlsDHConfig a, TlsDHConfig b)","org.bouncycastle.tls.DefaultTlsDHConfigVerifier").
method(3,"areParametersEqual(BigInteger[] pgA, BigInteger[] pgB)","org.bouncycastle.tls.DefaultTlsDHConfigVerifier").
method(3,"DHGroup(BigInteger p, BigInteger g)","org.bouncycastle.tls.crypto.DHGroup").
method(3,"DHGroup(BigInteger p, BigInteger q, BigInteger g)","org.bouncycastle.tls.crypto.DHGroup").
method(3,"addNegotiatedDHEGroupsClientExtension(Hashtable extensions, short[] dheGroups)","org.bouncycastle.tls.TlsDHUtils").
method(3,"addNegotiatedDHEGroupsServerExtension(Hashtable extensions, short dheGroup)","org.bouncycastle.tls.TlsDHUtils").
method(3,"getNegotiatedDHEGroupsClientExtension(Hashtable extensions)","org.bouncycastle.tls.TlsDHUtils").
method(3,"getNegotiatedDHEGroupsServerExtension(Hashtable extensions)","org.bouncycastle.tls.TlsDHUtils").
method(3,"createNegotiatedDHEGroupsClientExtension(short[] dheGroups)","org.bouncycastle.tls.TlsDHUtils").
method(3,"createNegotiatedDHEGroupsServerExtension(short dheGroup)","org.bouncycastle.tls.TlsDHUtils").
method(3,"readNegotiatedDHEGroupsClientExtension(byte[] extensionData)","org.bouncycastle.tls.TlsDHUtils").
method(3,"readNegotiatedDHEGroupsServerExtension(byte[] extensionData)","org.bouncycastle.tls.TlsDHUtils").
method(3,"getParametersForDHEGroup(short dheGroup)","org.bouncycastle.tls.TlsDHUtils").
method(3,"getFiniteFieldShortExponentBits(int namedGroup)","org.bouncycastle.tls.NamedGroup").
method(3,"absorb(byte[] data, int off, long databitlen)","org.bouncycastle.crypto.digests.KeccakDigest").
method(3,"messageEncrypt(byte[] input)","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi").
method(3,"messageDecrypt(byte[] input)","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceFujisakiCipherSpi").
method(3,"messageEncrypt(byte[] input)","org.bouncycastle.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi").
method(3,"messageDecrypt(byte[] input)","org.bouncycastle.pqc.jcajce.provider.mceliece.McEliecePointchevalCipherSpi").
method(3,"messageEncrypt()","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi").
method(3,"messageDecrypt()","org.bouncycastle.pqc.jcajce.provider.mceliece.McElieceKobaraImaiCipherSpi").
method(9,"getGostParams()","org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey").
method(8,"getGostParams()","org.bouncycastle.jcajce.provider.asymmetric.ecgost.BCECGOST3410PublicKey").
method(3,"BDSStateMap(BDSStateMap stateMap)","org.bouncycastle.pqc.crypto.xmss.BDSStateMap").
method(3,"compareByteArray(byte[] a, byte[] b)","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(2,"compareByteArray(byte[][], byte[][])","areEqual(byte[][], byte[][])","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(9,"nextAuthenticationPath(byte[] publicSeed, byte[] secretSeed, OTSHashAddress otsHashAddress)","org.bouncycastle.pqc.crypto.xmss.BDS").
method(3,"intToBytesBigEndianOffset(byte[] in, int value, int offset)","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(2,"longToBytesBigEndianOffset(byte[], long, int)","longToBigEndian(long, byte[], int)","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(3,"concat(byte[]... arrays)","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(5,"getNextState()","org.bouncycastle.pqc.crypto.xmss.BDS").
method(9,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters.Builder").
method(9,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.Builder").
method(9,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSSignature.Builder").
method(3,"ssl3Complete(TlsHash d, byte[] ipad, byte[] opad, int padLength)","org.bouncycastle.tls.CombinedHash").
method(3,"createSSl3HMAC(int macAlgorithm)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"deriveSSLKeyBlock(byte[] seed, int length)","org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret").
method(3,"deriveSSLMasterSecret(byte[] seed)","org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret").
method(3,"prf_SSL(byte[] seed, int md5Count)","org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret").
method(3,"deriveSSLKeyBlock(byte[] seed, int length)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret").
method(3,"deriveSSLMasterSecret(byte[] seed)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret").
method(3,"prf_SSL(byte[] seed, int md5Count)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret").
method(3,"isSSL(TlsCryptoParameters cryptoParams)","org.bouncycastle.tls.crypto.impl.TlsImplUtils").
method(3,"isSSL()","org.bouncycastle.tls.ProtocolVersion").
method(2,"isSSL(TlsContext)","isTLSv10(TlsContext)","org.bouncycastle.tls.TlsUtils").
method(9,"setNb(int Nb)","org.bouncycastle.crypto.modes.KCCMBlockCipher").
method(3,"withBDSState(Map<Integer,BDS> val)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters.Builder").
method(3,"withPrivateKey(byte[] privateKeyVal, XMSS xmssVal)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters.Builder").
method(3,"nextAuthenticationPath(XMSSPrivateKeyParameters privateKey, OTSHashAddress otsHashAddress)","org.bouncycastle.pqc.crypto.xmss.BDS").
method(3,"setXMSS(XMSS xmss)","org.bouncycastle.pqc.crypto.xmss.BDS").
method(3,"withPrivateKey(byte[] privateKeyVal, XMSS xmssVal)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.Builder").
method(3,"getXMSS()","org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters").
method(8,"getXMSS()","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(3,"initialize(XMSSPrivateKeyParameters privateKey, OTSHashAddress otsHashAddress)","org.bouncycastle.pqc.crypto.xmss.BDS").
method(9,"BDS(XMSS xmss)","org.bouncycastle.pqc.crypto.xmss.BDS").
method(3,"DSTU7624Mac(int blockBitLength, int keyBitLength, int q)","org.bouncycastle.crypto.macs.DSTU7624Mac").
method(3,"DSTU7624WrapEngine(int blockBitLength, int keyBitLength)","org.bouncycastle.crypto.engines.DSTU7624WrapEngine").
method(3,"DSTU7624Engine(int blockBitLength, int keyBitLength)","org.bouncycastle.crypto.engines.DSTU7624Engine").
method(5,"enableThreadOverride(String)","org.bouncycastle.util.Properties").
method(5,"disableThreadOverride(String)","org.bouncycastle.util.Properties").
method(9,"initCipherEncrypt(McElieceCCA2PublicKeyParameters pubKey)","org.bouncycastle.pqc.crypto.mceliece.McEliecePointchevalCipher").
method(9,"initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey)","org.bouncycastle.pqc.crypto.mceliece.McEliecePointchevalCipher").
method(9,"initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey)","org.bouncycastle.pqc.crypto.mceliece.McElieceKobaraImaiCipher").
method(9,"initCipherEncrypt(McEliecePublicKeyParameters pubKey)","org.bouncycastle.pqc.crypto.mceliece.McElieceCipher").
method(9,"initCipherDecrypt(McEliecePrivateKeyParameters privKey)","org.bouncycastle.pqc.crypto.mceliece.McElieceCipher").
method(9,"initCipherDecrypt(McElieceCCA2PrivateKeyParameters privKey)","org.bouncycastle.pqc.crypto.mceliece.McElieceFujisakiCipher").
method(3,"BCXMSSMTPublicKey(XMSSMTPublicKeyParameters keyParams)","org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPublicKey").
method(9,"getTreeDigestOID()","org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey").
method(3,"BCXMSSMTPrivateKey(XMSSMTPrivateKeyParameters keyParams)","org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey").
method(3,"BCXMSSPrivateKey(XMSSPrivateKeyParameters keyParams)","org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey").
method(3,"BCXMSSPublicKey(XMSSPublicKeyParameters keyParams)","org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPublicKey").
method(9,"getKeyParams()","org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSMTPrivateKey").
method(9,"getKeyParams()","org.bouncycastle.pqc.jcajce.provider.xmss.BCXMSSPrivateKey").
method(7,"update(byte in)","org.bouncycastle.crypto.macs.DSTU7624Mac").
method(7,"update(byte[] in, int inOff, int len)","org.bouncycastle.crypto.macs.DSTU7624Mac").
method(2,"getFinalPrivateKey()","getUpdatedPrivateKey()","org.bouncycastle.pqc.crypto.xmss.XMSSMTSigner").
method(2,"getFinalPrivateKey()","getUpdatedPrivateKey()","org.bouncycastle.pqc.crypto.xmss.XMSSSigner").
method(3,"getFinalPrivateKey()","org.bouncycastle.pqc.crypto.StatefulMessageSigner").
method(2,"processAADBytes(byte[], int, int, byte[], int)","processAAD(byte[], int, int)","org.bouncycastle.crypto.modes.KGCMBlockCipher").
method(7,"processByte(byte in, byte[] out, int outOff)","org.bouncycastle.crypto.modes.KGCMBlockCipher").
method(7,"processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)","org.bouncycastle.crypto.modes.KGCMBlockCipher").
method(7,"processByte(byte in, byte[] out, int outOff)","org.bouncycastle.crypto.modes.KCCMBlockCipher").
method(7,"processBytes(byte[] in, int inOff, int len, byte[] out, int outOff)","org.bouncycastle.crypto.modes.KCCMBlockCipher").
method(3,"DTLSServerProtocol(SecureRandom secureRandom)","org.bouncycastle.tls.DTLSServerProtocol").
method(3,"DTLSClientProtocol(SecureRandom secureRandom)","org.bouncycastle.tls.DTLSClientProtocol").
method(3,"DTLSProtocol(SecureRandom secureRandom)","org.bouncycastle.tls.DTLSProtocol").
method(1,"getWOTSPlusSecretKey(byte[], OTSHashAddress)","org-bouncycastle-pqc-crypto-xmss-xmss,org.bouncycastle.pqc.crypto.xmss.WOTSPlus").
method(3,"getKhf()","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(2,"getBDSState()","getPrivateKey()","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(9,"getBDSState()","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(9,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.Builder").
method(3,"getPrivateKey()","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(3,"getPublicKey()","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(1,"randomizeHash(WOTSPlus, XMSSNode, XMSSNode, XMSSAddress)","org-bouncycastle-pqc-crypto-xmss-xmss,org.bouncycastle.pqc.crypto.xmss.XMSSNodeUtil").
method(1,"lTree(WOTSPlus, WOTSPlusPublicKeyParameters, LTreeAddress)","org-bouncycastle-pqc-crypto-xmss-xmss,org.bouncycastle.pqc.crypto.xmss.XMSSNodeUtil").
method(1,"getRootNodeFromSignature(WOTSPlus, int, byte[], XMSSReducedSignature, OTSHashAddress, int)","org-bouncycastle-pqc-crypto-xmss-xmss,org.bouncycastle.pqc.crypto.xmss.XMSSVerifierUtil").
method(9,"getWOTSPlus()","org.bouncycastle.pqc.crypto.xmss.XMSSParameters").
method(9,"getK()","org.bouncycastle.pqc.crypto.xmss.XMSSParameters").
method(9,"importKeys(byte[] secretKeySeed, byte[] publicSeed)","org.bouncycastle.pqc.crypto.xmss.WOTSPlus").
method(7,"importState(byte[] privateKey, byte[] publicKey)","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(7,"importState(byte[] privateKey, byte[] publicKey)","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(3,"XMSSMT(XMSSMTParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(2,"getIndex()","getPrivateKey()","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(3,"getBDSState()","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(3,"XMSSParameters(int height, Digest digest, SecureRandom prng)","org.bouncycastle.pqc.crypto.xmss.XMSSParameters").
method(5,"getPRNG()","org.bouncycastle.pqc.crypto.xmss.XMSSParameters").
method(3,"XMSS(XMSSParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(3,"XMSSMTParameters(int height, int layers, Digest digest, SecureRandom prng)","org.bouncycastle.pqc.crypto.xmss.XMSSMTParameters").
method(9,"getBDSState()","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(8,"getFinalPrivateKey()","org.bouncycastle.pqc.crypto.StatefulMessageSigner").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters.Builder").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters.Builder").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters.Builder").
method(7,"XMSSReducedSignature(Builder builder)","org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature.Builder").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature.Builder").
method(7,"importState(byte[] privateKey, byte[] publicKey)","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.Builder").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSSignature.Builder").
method(2,"handleWarningMessage(short)","handleAlertWarningMessage(short)","org.bouncycastle.tls.TlsServerProtocol").
method(3,"handleWarningMessage(short description)","org.bouncycastle.tls.TlsProtocol").
method(2,"failWithError(short, short, String, Throwable)","handleFailure()","org.bouncycastle.tls.TlsProtocol").
method(2,"raiseAlert(short, short, String, Throwable)","raiseAlertWarning(short, String)","org.bouncycastle.tls.TlsProtocol").
method(3,"raiseWarning(short alertDescription, String message)","org.bouncycastle.tls.TlsProtocol").
method(2,"handleWarningMessage(short)","handleAlertWarningMessage(short)","org.bouncycastle.crypto.tls.TlsServerProtocol").
method(3,"handleWarningMessage(short description)","org.bouncycastle.crypto.tls.TlsProtocol").
method(2,"failWithError(short, short, String, Throwable)","handleFailure()","org.bouncycastle.crypto.tls.TlsProtocol").
method(2,"raiseAlert(short, short, String, Throwable)","raiseAlertWarning(short, String)","org.bouncycastle.crypto.tls.TlsProtocol").
method(3,"raiseWarning(short alertDescription, String message)","org.bouncycastle.crypto.tls.TlsProtocol").
method(3,"getCause()","org.bouncycastle.tls.crypto.TlsCryptoException").
method(3,"createNonce(int size)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(2,"createNonce(int)","createNonceGenerator(byte[])","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(3,"getCause()","org.bouncycastle.tls.TlsFatalAlert").
method(3,"getCause()","org.bouncycastle.crypto.tls.TlsFatalAlert").
method(9,"getTagNo()","org.bouncycastle.asn1.ASN1TaggedObjectParser").
method(9,"getObjectParser(int tag, boolean isExplicit)","org.bouncycastle.asn1.ASN1TaggedObjectParser").
method(3,"deriveUsingPRF(int prfAlgorithm, byte[] labelSeed, int length)","org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret").
method(3,"deriveUsingPRF(int prfAlgorithm, byte[] labelSeed, int length)","org.bouncycastle.tls.crypto.impl.jcajce.JceTlsSecret").
method(7,"encodePlaintext(long seqNo, short type, byte[] plaintext, int offset, int len)","org.bouncycastle.crypto.tls.TlsBlockCipher").


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
