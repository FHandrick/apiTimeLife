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

method(3,"engineInitSign(PrivateKey privateKey)","org.bouncycastle.jcajce.provider.asymmetric.ec.GMSignatureSpi").
method(3,"exportBDSState()","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(3,"getBDS()","org.bouncycastle.pqc.crypto.xmss.XMSSMT").
method(2,"withPrivateKey(byte[])","withBDSState(Map)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters.Builder").
method(3,"validate(boolean isStateForRootTree)","org.bouncycastle.pqc.crypto.xmss.BDS").
method(3,"importState(byte[] privateKey, byte[] publicKey, byte[] bdsState)","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(2,"importKeys(byte[], byte[])","importState(byte[], byte[])","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(3,"exportBDSState()","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(3,"getBDS()","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(3,"withPrivateKey(byte[] val)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.Builder").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters.Builder").
method(7,"build()","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters.Builder").
method(8,"getHeaders()","org.bouncycastle.est.ESTRequest").
method(3,"XMSSAddress(int type)","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(3,"parseByteArray(byte[] address)","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(3,"setLayerAddress(int layerAddress)","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(3,"setTreeAddress(long treeAddress)","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(3,"setType(int type)","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(3,"setKeyAndMask(int keyAndMask)","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(5,"getByteRepresentation()","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(3,"XMSSPublicKeyParameters(XMSSParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters").
method(2,"parseByteArray(byte[])","(Builder)","org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters").
method(3,"setRoot(byte[] root)","org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters").
method(3,"setPublicSeed(byte[] publicSeed)","org.bouncycastle.pqc.crypto.xmss.XMSSPublicKeyParameters").
method(3,"setHeight(int height)","org.bouncycastle.pqc.crypto.xmss.XMSSNode").
method(3,"setValue(byte[] value)","org.bouncycastle.pqc.crypto.xmss.XMSSNode").
method(3,"XMSSMTPrivateKeyParameters(XMSSMTParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(2,"parseByteArray(byte[])","(Builder)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(3,"setIndex(long index)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(3,"setSecretKeySeed(byte[] secretKeySeed)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(3,"setSecretKeyPRF(byte[] secretKeyPRF)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(3,"setPublicSeed(byte[] publicSeed)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(3,"setRoot(byte[] root)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPrivateKeyParameters").
method(3,"OTSHashAddress()","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(3,"parseByteArray(byte[] address)","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(3,"setOTSAddress(int otsAddress)","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(3,"setChainAddress(int chainAddress)","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(3,"setHashAddress(int hashAddress)","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(3,"WOTSPlusPrivateKeyParameters(WOTSPlusParameters params)","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPrivateKeyParameters").
method(3,"getPrivateKey()","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPrivateKeyParameters").
method(2,"setPrivateKey(byte[][])","(WOTSPlusParameters, byte[][])","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPrivateKeyParameters").
method(3,"LTreeAddress()","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(3,"parseByteArray(byte[] address)","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(5,"setLTreeAddress(int)","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(3,"setTreeHeight(int treeHeight)","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(3,"setTreeIndex(int treeIndex)","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(3,"parseByteArray(byte[] in)","org.bouncycastle.pqc.crypto.xmss.XMSSStoreableObjectInterface").
method(3,"WOTSPlusSignature(WOTSPlusParameters params)","org.bouncycastle.pqc.crypto.xmss.WOTSPlusSignature").
method(3,"getSignature()","org.bouncycastle.pqc.crypto.xmss.WOTSPlusSignature").
method(2,"setSignature(byte[][])","(WOTSPlusParameters, byte[][])","org.bouncycastle.pqc.crypto.xmss.WOTSPlusSignature").
method(3,"XMSSMTPublicKeyParameters(XMSSMTParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters").
method(2,"parseByteArray(byte[])","(Builder)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters").
method(3,"setRoot(byte[] root)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters").
method(3,"setPublicSeed(byte[] publicSeed)","org.bouncycastle.pqc.crypto.xmss.XMSSMTPublicKeyParameters").
method(3,"XMSSReducedSignature(XMSSParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature").
method(2,"parseByteArray(byte[])","(Builder)","org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature").
method(3,"getSignature()","org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature").
method(3,"setSignature(WOTSPlusSignature signature)","org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature").
method(3,"setAuthPath(List<XMSSNode> authPath)","org.bouncycastle.pqc.crypto.xmss.XMSSReducedSignature").
method(3,"XMSSMTSignature(XMSSMTParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature").
method(2,"parseByteArray(byte[])","(Builder)","org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature").
method(3,"setIndex(long index)","org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature").
method(3,"setRandom(byte[] random)","org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature").
method(3,"setReducedSignatures(List<XMSSReducedSignature> reducedSignatures)","org.bouncycastle.pqc.crypto.xmss.XMSSMTSignature").
method(3,"HashTreeAddress()","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(3,"parseByteArray(byte[] address)","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(3,"setTreeHeight(int treeHeight)","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(3,"setTreeIndex(int treeIndex)","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(2,"treeSig(byte[], OTSHashAddress)","wotsSign(byte[], OTSHashAddress)","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(3,"XMSSPrivateKeyParameters(XMSSParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(2,"parseByteArray(byte[])","(Builder)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(3,"setIndex(int index)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(3,"setSecretKeySeed(byte[] secretKeySeed)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(3,"setSecretKeyPRF(byte[] secretKeyPRF)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(3,"setPublicSeed(byte[] publicSeed)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(3,"setRoot(byte[] root)","org.bouncycastle.pqc.crypto.xmss.XMSSPrivateKeyParameters").
method(3,"XMSSSignature(XMSSParameters params)","org.bouncycastle.pqc.crypto.xmss.XMSSSignature").
method(3,"parseByteArray(byte[] in)","org.bouncycastle.pqc.crypto.xmss.XMSSSignature").
method(3,"setIndex(int index)","org.bouncycastle.pqc.crypto.xmss.XMSSSignature").
method(2,"setRandom(byte[])","(Builder)","org.bouncycastle.pqc.crypto.xmss.XMSSSignature").
method(3,"WOTSPlusPublicKeyParameters(WOTSPlusParameters params)","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPublicKeyParameters").
method(3,"getPublicKey()","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPublicKeyParameters").
method(2,"setPublicKey(byte[][])","(WOTSPlusParameters, byte[][])","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPublicKeyParameters").
method(3,"H(byte[] in, byte[] pubSeed, XMSSAddress addr)","org.bouncycastle.pqc.crypto.xmss.KeyedHashFunctions").
method(9,"toByteArray()","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(9,"getLayerAddress()","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(9,"getTreeAddress()","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(9,"XMSSNode(int height, byte[] value)","org.bouncycastle.pqc.crypto.xmss.XMSSNode").
method(9,"clone()","org.bouncycastle.pqc.crypto.xmss.XMSSNode").
method(9,"toByteArray()","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(9,"getOTSAddress()","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(9,"getChainAddress()","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(9,"getHashAddress()","org.bouncycastle.pqc.crypto.xmss.OTSHashAddress").
method(9,"toByteArray()","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPrivateKeyParameters").
method(9,"toByteArray()","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(9,"getLTreeAddress()","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(9,"getTreeHeight()","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(9,"getTreeIndex()","org.bouncycastle.pqc.crypto.xmss.LTreeAddress").
method(9,"toByteArray()","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(9,"getPadding()","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(9,"getTreeHeight()","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(9,"getTreeIndex()","org.bouncycastle.pqc.crypto.xmss.HashTreeAddress").
method(9,"toByteArray()","org.bouncycastle.pqc.crypto.xmss.WOTSPlusPublicKeyParameters").
method(9,"getLen()","org.bouncycastle.pqc.crypto.xmss.WOTSPlusParameters").
method(9,"KeyedHashFunctions(Digest digest, int digestSize)","org.bouncycastle.pqc.crypto.xmss.KeyedHashFunctions").
method(9,"F(byte[] key, byte[] in)","org.bouncycastle.pqc.crypto.xmss.KeyedHashFunctions").
method(9,"H(byte[] key, byte[] in)","org.bouncycastle.pqc.crypto.xmss.KeyedHashFunctions").
method(9,"HMsg(byte[] key, byte[] in)","org.bouncycastle.pqc.crypto.xmss.KeyedHashFunctions").
method(9,"PRF(byte[] key, byte[] address)","org.bouncycastle.pqc.crypto.xmss.KeyedHashFunctions").
method(8,"getKeyAndMask()","org.bouncycastle.pqc.crypto.xmss.XMSSAddress").
method(10,getlayeraddress,org-bouncycastle-pqc-crypto-xmss-xmssaddress).
method(10,gettreeaddress,org-bouncycastle-pqc-crypto-xmss-xmssaddress).
method(10,gettype,org-bouncycastle-pqc-crypto-xmss-xmssaddress).
method(3,"testName(String name, String dnsName, Set<String> suffixes)","org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer").
method(3,"bytesToIntBigEndian(byte[] in, int offset)","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(3,"bytesToLongBigEndian(byte[] in, int offset)","org.bouncycastle.pqc.crypto.xmss.XMSSUtil").
method(3,"lTree(WOTSPlusPublicKey publicKey, LTreeAddress address)","org.bouncycastle.pqc.crypto.xmss.XMSS").
method(9,"nextAuthenticationPath(OTSHashAddress otsHashAddress)","org.bouncycastle.pqc.crypto.xmss.BDS").
method(9,"getOid()","org.bouncycastle.pqc.crypto.xmss.XMSSOid").
method(9,"toString()","org.bouncycastle.pqc.crypto.xmss.XMSSOid").
method(8,"getPublicKeyFromSignature(byte[] messageDigest, WOTSPlusSignature signature, OTSHashAddress otsHashAddress)","org.bouncycastle.pqc.crypto.xmss.WOTSPlus").
method(8,"getPrivateKey()","org.bouncycastle.pqc.crypto.xmss.WOTSPlus").
method(8,"getPublicKey(OTSHashAddress otsHashAddress)","org.bouncycastle.pqc.crypto.xmss.WOTSPlus").
method(8,"getOid()","org.bouncycastle.pqc.crypto.xmss.WOTSPlusParameters").
method(3,"addAttribute(String key, Map<String,String> attributeMap)","org.bouncycastle.jce.provider.BouncyCastleProvider").
method(3,"addAttribute(String key, Map<String,String> attributeMap)","org.bouncycastle.pqc.jcajce.provider.BouncyCastlePQCProvider").
method(3,"testName(String name, String dnsName)","org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer").
method(7,"testName(String name, String dnsName)","org.bouncycastle.est.jcajce.JsseDefaultHostnameAuthorizer").
method(3,"getDefaultSignatureAlgorithms(int signatureAlgorithm)","org.bouncycastle.tls.TlsUtils").
method(3,"chooseSignatureAndHashAlgorithm(TlsContext context, Vector algs, int signatureAlgorithm)","org.bouncycastle.tls.TlsUtils").
method(7,"getCipherType(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(7,"getEncryptionAlgorithm(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(7,"getKeyExchangeAlgorithm(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(7,"getMACAlgorithm(int ciphersuite)","org.bouncycastle.crypto.tls.TlsUtils").
method(3,"BcTlsCrypto(TlsCryptoCapabilities capabilities, SecureRandom entropySource)","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"getSupportedNamedCurves()","org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto").
method(3,"setCapabilities(TlsCryptoCapabilities cryptoCapabilities)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCryptoProvider").
method(3,"JcaTlsCrypto(TlsCryptoCapabilities capabilities, JcaJceHelper helper, SecureRandom entropySource, SecureRandom nonceEntropySource)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(3,"getSupportedNamedCurves()","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(9,"PKIData(ASN1Sequence seq)","org.bouncycastle.asn1.cmc.PKIData").
method(3,"handleHandshakeMessage(short type, byte[] data)","org.bouncycastle.tls.TlsClientProtocol").
method(3,"size()","org.bouncycastle.tls.ByteQueue").
method(3,"handleHandshakeMessage(short type, byte[] data)","org.bouncycastle.tls.TlsServerProtocol").
method(3,"handleHandshakeMessage(short type, byte[] buf)","org.bouncycastle.tls.TlsProtocol").
method(3,"handleHandshakeMessage(short type, byte[] data)","org.bouncycastle.crypto.tls.TlsClientProtocol").
method(3,"size()","org.bouncycastle.crypto.tls.ByteQueue").
method(3,"handleHandshakeMessage(short type, byte[] data)","org.bouncycastle.crypto.tls.TlsServerProtocol").
method(3,"handleHandshakeMessage(short type, byte[] buf)","org.bouncycastle.crypto.tls.TlsProtocol").
method(7,"engineSetMode(String mode)","org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher").
method(5,"getCurrentPRFHash(TlsContext, TlsHandshakeHash, byte[])","org.bouncycastle.tls.TlsProtocol").
method(3,"DefaultESTClientSourceProvider(SSLSocketFactory socketFactory, HostnameAuthorizer<SSLSession> hostNameAuthorizer, int timeout, ChannelBindingProvider bindingProvider, Set<String> cipherSuites, Long absoluteLimit)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"JcaDefaultESTHttpClientProvider(JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, SSLSocketFactoryCreator socketFactoryCreator, int timeout, ChannelBindingProvider bindingProvider, Set<String> cipherSuites, Long absoluteLimit)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withHostNameAuthorizer(JcaJceHostNameAuthorizer hostNameAuthorizer)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"DefaultESTClientSourceProvider(SSLSocketFactory socketFactory, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, int timeout, ChannelBindingProvider bindingProvider, Set<String> cipherSuites, Long absoluteLimit)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"JcaDefaultESTHttpClientProvider(JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, SocketFactoryCreator socketFactoryCreator, int timeout, ChannelBindingProvider bindingProvider, Set<String> cipherSuites, Long absoluteLimit)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"JcaESTServiceBuilder(String server, SocketFactoryCreator socketFactoryCreator)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(2,"withKeyManagerFactory(KeyManagerFactory)","withKeyManagers(KeyManager[])","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(3,"setRevocationLists(CRL[] revocationLists)","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(8,"getCertPathTrustManager(final Set<TrustAnchor> anchors, final CRL[] revocationLists)","org.bouncycastle.est.jcajce.JcaJceUtils").
method(3,"JcaJceSocketFactoryCreatorBuilder()","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(3,"JcaJceSocketFactoryCreatorBuilder(Set<TrustAnchor> trustAnchors)","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(3,"withKeyManagerFactory(String type, String provider, KeyStore clientKeyStore, char[] clientKeyStorePass)","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(3,"setEstAuthorizer(JcaJceAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(3,"makeAuthorizerWithoutTrustAnchors()","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(3,"makeAuthorizerWithTrustAnchors()","org.bouncycastle.est.jcajce.JcaJceSocketFactoryCreatorBuilder").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL[] revocationLists, JcaJceAuthorizer estAuthorizer, String tlsVersion, String tlsProvider, int timeout, ChannelBindingProvider bindingProvider, Set<String> cipherSuites, Long absoluteLimit)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"createFactory(String tlsVersion, String tlsProvider, KeyManagerFactory keyManagerFactory, final JcaJceAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"JcaESTServiceBuilder(String server)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"JcaESTServiceBuilder(String server, Set<TrustAnchor> tlsTrustAnchors)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"withClientKeystore(KeyStore clientKeystore, char[] clientKeystorePassword)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"withRevocationLists(CRL[] revocationLists)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"withTlsVersion(String tlsVersion)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"withTlSProvider(String tlsProvider)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"getCertPathTLSAuthorizer(final CRL[] revocationLists, final Set<TrustAnchor> tlsTrustAnchors)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"getSupportedEllipticCurvesExtension(Hashtable extensions, Set<Integer> acceptedCurves)","org.bouncycastle.tls.TlsECCUtils").
method(3,"readSupportedEllipticCurvesExtension(byte[] extensionData, Set<Integer> acceptedCurves)","org.bouncycastle.tls.TlsECCUtils").
method(3,"JcaTlsCrypto(JcaJceHelper helper, SecureRandom entropySource, SecureRandom nonceEntropySource)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsCrypto").
method(9,"doDigestFunction(ESTResponse res)","org.bouncycastle.est.HttpAuth").
method(3,"HttpAuth(String username, String password, SecureRandom nonceGenerator)","org.bouncycastle.est.HttpAuth").
method(3,"HttpAuth(String realm, String username, String password, SecureRandom nonceGenerator)","org.bouncycastle.est.HttpAuth").
method(3,"HttpAuth(String username, String password, SecureRandom nonceGenerator)","org.bouncycastle.est.HttpAuth").
method(7,"getCSRAttributes()","org.bouncycastle.est.ESTService").
method(3,"getWriter()","org.bouncycastle.est.ESTRequest").
method(3,"withClientRequestIdempotentInputSource(ESTClientRequestIdempotentInputSource writer)","org.bouncycastle.est.ESTRequestBuilder").
method(3,"HttpAuth(String username, String password)","org.bouncycastle.est.HttpAuth").
method(3,"HttpAuth(String realm, String username, String password)","org.bouncycastle.est.HttpAuth").
method(3,"ESTRequestBuilder(String method, URL url, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequestBuilder").
method(2,"withESTClient(ESTClient)","withClient(ESTClient)","org.bouncycastle.est.ESTRequestBuilder").
method(2,"getEstClient()","getClient()","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTClientRequestIdempotentInputSource writer, ESTHijacker hijacker, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTHijacker hijacker, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"newWithURL(URL url)","org.bouncycastle.est.ESTRequest").
method(2,"getUrl()","getURL()","org.bouncycastle.est.ESTRequest").
method(3,"CACertsResponse(Store<X509CertificateHolder> store, ESTRequest requestToRetry, Source session, boolean trusted)","org.bouncycastle.est.CACertsResponse").
method(2,"hasStore()","hasCertificates()","org.bouncycastle.est.CACertsResponse").
method(2,"getStore()","getCertificateStore()","org.bouncycastle.est.CACertsResponse").
method(3,"ESTRequest(String method, URL url, ESTClientRequestIdempotentInputSource writer, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTClientRequestIdempotentInputSource writer, ESTHijacker hijacker, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTHijacker hijacker, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"setEstClient(ESTClient estClient)","org.bouncycastle.est.ESTRequest").
method(2,"addCipherSuit(String)","addCipherSuites(String)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(2,"addCipherSuit(String[])","addCipherSuites(String[])","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(1,"addHeader(String, String)","org-bouncycastle-est-estrequest,org.bouncycastle.est.ESTRequestBuilder").
method(3,"copy()","org.bouncycastle.est.ESTRequest").
method(1,"setHeader(String, String)","org-bouncycastle-est-estrequest,org.bouncycastle.est.ESTRequestBuilder").
method(3,"newWithHijacker(ESTHijacker estHttpHijacker)","org.bouncycastle.est.ESTRequest").
method(3,"getReadAheadBuf()","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTClientRequestInputSource writer, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTClientRequestInputSource writer, ESTHijacker hijacker, ESTSourceConnectionListener listener)","org.bouncycastle.est.ESTRequest").
method(3,"SSLSocketSource(SSLSocket sock, ChannelBindingProvider bindingProvider)","org.bouncycastle.est.jcajce.SSLSocketSource").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL[] revocationLists, JcaJceAuthorizer estAuthorizer, String tlsVersion, String tlsProvider, int timeout, ChannelBindingProvider bindingProvider, Set<String> cipherSuites)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"DefaultESTClientSourceProvider(SSLSocketFactory socketFactory, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, int timeout, ChannelBindingProvider bindingProvider, Set<String> cipherSuites)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"ESTException(String message, int statusCode, InputStream body, int contentLength)","org.bouncycastle.est.ESTException").
method(3,"getCause()","org.bouncycastle.est.ESTException").
method(8,"getHeaders()","org.bouncycastle.est.ESTResponse").
method(8,"getContentLength()","org.bouncycastle.est.ESTResponse").
method(8,"getHeaders()","org.bouncycastle.est.ESTRequest").
method(8,"getWriter()","org.bouncycastle.est.ESTRequest").
method(7,"getStreamVerifier(DigitallySigned signature)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRSAVerifier").
method(7,"getStreamSigner(SignatureAndHashAlgorithm algorithm)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRSASigner").
method(2,"verifySignature(DigitallySigned, byte[])","verifyRawSignature(DigitallySigned, byte[])","org.bouncycastle.tls.crypto.impl.bc.BcTlsRSAVerifier").
method(2,"verifySignature(DigitallySigned, byte[])","verifyRawSignature(DigitallySigned, byte[])","org.bouncycastle.tls.crypto.impl.bc.BcTlsDSSVerifier").
method(2,"verifySignature(DigitallySigned, byte[])","verifyRawSignature(DigitallySigned, byte[])","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRSAVerifier").
method(2,"verifySignature(DigitallySigned, byte[])","verifyRawSignature(DigitallySigned, byte[])","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsDSAVerifier").
method(2,"verifySignature(DigitallySigned, byte[])","verifyRawSignature(DigitallySigned, byte[])","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsECDSAVerifier").
method(3,"CombinedHash(TlsContext context)","org.bouncycastle.tls.CombinedHash").
method(3,"notifyPRFDetermined()","org.bouncycastle.tls.CombinedHash").
method(3,"trackHashAlgorithm(short hashAlgorithm)","org.bouncycastle.tls.CombinedHash").
method(3,"sealHashAlgorithms()","org.bouncycastle.tls.CombinedHash").
method(3,"stopTracking()","org.bouncycastle.tls.CombinedHash").
method(3,"forkPRFHash()","org.bouncycastle.tls.CombinedHash").
method(3,"getFinalHash(short hashAlgorithm)","org.bouncycastle.tls.CombinedHash").
method(3,"getDefaultSupportedSignatureAlgorithms()","org.bouncycastle.tls.TlsUtils").
method(7,"verifySignature(DigitallySigned signedParams, byte[] hash)","org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsRSAVerifier").
method(3,"ESTRequest(String method, URL url, ESTClientRequestInputSource writer)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTClientRequestInputSource writer, ESTHijacker hijacker)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTHijacker hijacker)","org.bouncycastle.est.ESTRequest").
method(3,"SSLSocketSource(SSLSocket sock)","org.bouncycastle.est.jcajce.SSLSocketSource").
method(3,"getUnique()","org.bouncycastle.est.jcajce.SSLSocketSource").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL[] revocationLists, JcaJceAuthorizer estAuthorizer, String tlsVersion)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"createFactory(String tlsVersion, KeyManagerFactory keyManagerFactory, final JcaJceAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"DefaultESTClientSourceProvider(SSLSocketFactory socketFactory, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(2,"wrapSocket(Socket, String, int)","makeSource(String, int)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL[] revocationLists, JcaJceAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"createFactory(KeyManagerFactory keyManagerFactory, final JcaJceAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, JcaJceHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL revocationList, JcaJceAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withRevocationList(CRL revocationList)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"getCertPathTLSAuthorizer(final CRL revocationList, final Set<TrustAnchor> tlsTrustAnchors)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, ESTHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL revocationList, ESTAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"createFactory(KeyManagerFactory keyManagerFactory, final ESTAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withHostNameAuthorizer(ESTHostNameAuthorizer hostNameAuthorizer)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"DefaultESTClientSourceProvider(SSLSocketFactory socketFactory, ESTHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(8,"getCertPathTLSAuthorizer(final CRL revocationList, final Set<TrustAnchor> tlsTrustAnchors)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"withHostNameAuthorizer(TLSHostNameAuthorizer hostNameAuthorizer)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"withTlsAuthorizer(ESTAuthorizer ESTAuthorizer)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"getHostNameAuthorizer()","org.bouncycastle.est.ESTService").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL revocationList, ESTAuthorizer estAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withHostNameAuthorizer(TLSHostNameAuthorizer hostNameAuthorizer)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"DefaultESTClientSourceProvider(SSLSocketFactory socketFactory, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"DefaultESTClientSourceProvider(TLSAcceptedIssuersSource tlsAcceptedIssuersSource, ESTAuthorizer serverESTAuthorizer, KeyManagerFactory keyManagerFactory, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"getUsingDefaultSSLSocketFactory(TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"getUsingDefaultSSLSocketFactory(KeyManagerFactory keyManagerFactory, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"getCertPathTLSAuthorizer(final CRL revocationList)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(1,"createFactory(KeyManagerFactory, ESTAuthorizer)","org-bouncycastle-est-jcajce-defaultestclientsourceprovider,org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withTlsAuthorizer(TLSAuthorizer tlsAuthorizer)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL revocationList, TLSAuthorizer tlsAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withTlsTrustAnchors(Set<TrustAnchor> tlsTrustAnchors)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"DefaultESTClientSourceProvider(TLSAcceptedIssuersSource tlsAcceptedIssuersSource, TLSAuthorizer serverTLSAuthorizer, KeyManagerFactory keyManagerFactory, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(8,"getCertPathTLSAuthorizer(final CRL revocationList)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"DigestAuth(String username, String password)","org.bouncycastle.est.DigestAuth").
method(3,"DigestAuth(String realm, String username, String password)","org.bouncycastle.est.DigestAuth").
method(7,"simpleEnroll(boolean reenroll, PKCS10CertificationRequest certificationRequest, ESTAuth auth)","org.bouncycastle.est.ESTService").
method(7,"handleEnrollResponse(ESTResponse resp)","org.bouncycastle.est.ESTService").
method(7,"getCSRAttributes()","org.bouncycastle.est.ESTService").
method(9,"ready(OutputStream os)","org.bouncycastle.est.ESTClientRequestInputSource").
method(7,"makeClient()","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(7,"DefaultESTClientSourceProvider(TLSAcceptedIssuersSource tlsAcceptedIssuersSource, TLSAuthorizer serverTLSAuthorizer, KeyManagerFactory keyManagerFactory, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(7,"getUsingDefaultSSLSocketFactory(TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(3,"CACertsResponse(Store<X509CertificateHolder> store, ESTRequest requestToRetry, Source session)","org.bouncycastle.est.ESTService.CACertsResponse").
method(7,"createFactory()","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(7,"wrapSocket(Socket plainSocket, String host, int port)","org.bouncycastle.est.jcajce.DefaultESTClientSourceProvider").
method(7,"doDigestFunction(ESTResponse res)","org.bouncycastle.est.DigestAuth").
method(7,"doRequest(ESTRequest c)","org.bouncycastle.est.ESTClient").
method(7,"ESTResponse(ESTRequest originalRequest, Source source)","org.bouncycastle.est.ESTResponse").
method(7,"readStringIncluding(char until)","org.bouncycastle.est.ESTResponse").
method(7,"close()","org.bouncycastle.est.ESTResponse").
method(7,"doRequest(ESTRequest req)","org.bouncycastle.est.jcajce.DefaultESTClient").
method(7,"redirectURL(ESTResponse response)","org.bouncycastle.est.jcajce.DefaultESTClient").
method(7,"performRequest(ESTRequest c)","org.bouncycastle.est.jcajce.DefaultESTClient").
method(3,"ESTRequest(String method, URL url, ESTClientRequestInputSource writer, ESTHttpHijacker hijacker)","org.bouncycastle.est.ESTRequest").
method(3,"ESTRequest(String method, URL url, ESTHttpHijacker hijacker)","org.bouncycastle.est.ESTRequest").
method(3,"newWithHijacker(ESTHttpHijacker estHttpHijacker)","org.bouncycastle.est.ESTRequest").
method(8,"getHijacker()","org.bouncycastle.est.ESTRequest").
method(2,"makeHttpClient()","makeClient()","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL revocationList, TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"DefaultESTClient(ESTClientSSLSocketProvider sslSocketProvider)","org.bouncycastle.est.jcajce.DefaultESTClient").
method(3,"withClientProvider(ESTHttpClientProvider clientProvider)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"simpleEnroll(boolean reenroll, PKCS10CertificationRequest certificationRequest, ESTHttpAuth auth)","org.bouncycastle.est.ESTService").
method(3,"handleEnrollResponse(ESTHttpResponse resp)","org.bouncycastle.est.ESTService").
method(3,"CACertsResponse(Store<X509CertificateHolder> store, ESTHttpRequest requestToRetry, Source session)","org.bouncycastle.est.ESTService.CACertsResponse").
method(3,"EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTHttpRequest requestToRetry, Source session)","org.bouncycastle.est.ESTService.EnrollmentResponse").
method(3,"withClientProvider(ESTHttpClientProvider clientProvider)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(8,"getRequestToRetry()","org.bouncycastle.est.ESTService.CACertsResponse").
method(8,"getRequestToRetry()","org.bouncycastle.est.ESTService.EnrollmentResponse").
method(8,"makeHttpClient()","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withHostNameAuthorizer(TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"withTlsAuthorizer(TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"withHostNameAuthorizer(TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(8,"wrapSocket(Socket plainSocket, String host, int port)","org.bouncycastle.est.http.DefaultESTClientSSLSocketProvider").
method(8,"wrapSocket(Socket plainSocket, String host, int port)","org.bouncycastle.est.http.ESTClientSSLSocketProvider").
method(8,"getHostNameAuthorizer()","org.bouncycastle.est.ESTService").
method(3,"ESTHttpResponse(ESTHttpRequest originalRequest, Socket socket)","org.bouncycastle.est.http.ESTHttpResponse").
method(3,"ESTHttpResponse(ESTHttpRequest originalRequest, InputStream inputStream)","org.bouncycastle.est.http.ESTHttpResponse").
method(3,"getSocket()","org.bouncycastle.est.http.ESTHttpResponse").
method(3,"CSRRequestResponse(CSRAttributesResponse attributesResponse, SSLSession session)","org.bouncycastle.est.ESTService.CSRRequestResponse").
method(3,"CACertsResponse(Store<X509CertificateHolder> store, ESTHttpRequest requestToRetry, SSLSession session)","org.bouncycastle.est.ESTService.CACertsResponse").
method(3,"EnrollmentResponse(Store<X509CertificateHolder> store, long notBefore, ESTHttpRequest requestToRetry, SSLSession session)","org.bouncycastle.est.ESTService.EnrollmentResponse").
method(8,"getSession()","org.bouncycastle.est.ESTService.CSRRequestResponse").
method(8,"getSession()","org.bouncycastle.est.ESTService.CACertsResponse").
method(8,"getSession()","org.bouncycastle.est.ESTService.EnrollmentResponse").
method(3,"getCACerts(boolean tlsAcceptAny)","org.bouncycastle.est.ESTService").
method(3,"JcaDefaultESTHttpClientProvider(Set<TrustAnchor> tlsTrustAnchors, KeyStore clientKeystore, char[] clientKeystorePassword, TLSHostNameAuthorizer<SSLSession> hostNameAuthorizer, CRL revocationList)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"makeHttpClient(TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.jcajce.JcaDefaultESTHttpClientProvider").
method(3,"withTlsAuthorizer(TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.jcajce.JcaESTServiceBuilder").
method(3,"ESTServiceBuilder(Set<TrustAnchor> tlsTrustAnchors, String server)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"withClientKeystore(KeyStore clientKeystore)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"withClientKeystorePassword(char[] clientKeystorePassword)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"getTlsTrustAnchors()","org.bouncycastle.est.ESTService").
method(3,"getRevocationList()","org.bouncycastle.est.ESTService").
method(3,"getCACerts(RFC7030BootstrapAuthorizer<SSLSession> bootstrapAuthorizer, boolean tlsAcceptAny)","org.bouncycastle.est.ESTService").
method(3,"simpleEnroll(ESTEnrollmentResponse priorResponse)","org.bouncycastle.est.ESTService").
method(8,"simpleEnroll(boolean reenroll, PKCS10CertificationRequest certificationRequest, ESTHttpAuth auth)","org.bouncycastle.est.ESTService").
method(8,"handleEnrollResponse(ESTHttpResponse resp)","org.bouncycastle.est.ESTService").
method(8,"getCSRAttributes()","org.bouncycastle.est.ESTService").
method(3,"withTlsTrustAnchors(Set<TrustAnchor> tlsTrustAnchors)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"makeCSRAttributesClient(TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.ESTService").
method(3,"makeHttpClient(TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.ESTService").
method(3,"makeCACertsClient(TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.ESTService").
method(3,"makeEnrollmentClient(TLSAuthorizer<SSLSession> tlsAuthorizer)","org.bouncycastle.est.ESTService").
method(3,"ESTServiceBuilder()","org.bouncycastle.est.ESTServiceBuilder").
method(2,"withServer(String)","(String)","org.bouncycastle.est.ESTServiceBuilder").
method(3,"makeCACertsClient(final boolean tlsAcceptAny)","org.bouncycastle.est.ESTService").
method(3,"makeEnrollmentClient()","org.bouncycastle.est.ESTService").
method(3,"makeCSRAttributesClient()","org.bouncycastle.est.ESTService").
method(3,"setTlsTrustAnchors(X509Certificate[] tlsTrustAnchors)","org.bouncycastle.est.EST").
method(3,"main(String[] args)","org.bouncycastle.est.ExRunner").
method(8,"getTlsTrustAnchors()","org.bouncycastle.est.EST").
method(3,"withBasicAuth(String realm, String user, String password)","org.bouncycastle.est.http.ESTHttpRequest").
method(3,"ESTHttpException(String message, int statusCode, String message1, InputStream body, int contentLength)","org.bouncycastle.est.http.ESTHttpException").
method(3,"ESTHttpException(String message, int statusCode, String message1, InputStream body)","org.bouncycastle.est.http.ESTHttpException").
method(7,"getInstance(Object o)","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(3,"ControlsProcessed(BodyPartID[] bodyPartIDs)","org.bouncycastle.asn1.cmc.ControlsProcessed").
method(8,"getBodyList()","org.bouncycastle.asn1.cmc.CMCStatusInfoV2").
method(8,"getCertificates()","org.bouncycastle.cms.CMSSignedData").
method(8,"getCRLs()","org.bouncycastle.cms.CMSSignedData").
method(8,"getAttributeCertificates()","org.bouncycastle.cms.CMSSignedData").
method(3,"CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString)","org.bouncycastle.asn1.cmc.CMCStatusInfo").
method(2,"getcMCStatus()","getCMCStatus()","org.bouncycastle.asn1.cmc.CMCStatusInfo").
method(3,"getEncoded()","org.bouncycastle.asn1.cmc.CMCStatusInfo.OtherInfo").
method(9,"CMCStatusInfo(CMCStatus cMCStatus, ASN1Sequence bodyList, DERUTF8String statusString, OtherInfo otherInfo)","org.bouncycastle.asn1.cmc.CMCStatusInfo").
method(9,"CMCStatusInfo(ASN1Sequence seq)","org.bouncycastle.asn1.cmc.CMCStatusInfo").
method(9,"getInstance(Object obj)","org.bouncycastle.asn1.cmc.CMCStatusInfo.OtherInfo").
method(8,"getBodyList()","org.bouncycastle.asn1.cmc.CMCStatusInfo").
method(3,"TaggedAttribute(ASN1Integer bodyPartID, ASN1ObjectIdentifier attrType, ASN1Set attrValues)","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(3,"setBodyPartID(ASN1Integer bodyPartID)","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(3,"setAttrType(ASN1ObjectIdentifier attrType)","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(3,"setAttrValues(ASN1Set attrValues)","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(3,"equals(Object o)","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(3,"hashCode()","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(8,"getBodyPartID()","org.bouncycastle.asn1.cmc.TaggedAttribute").
method(8,"getUserIDs()","org.bouncycastle.openpgp.PGPPublicKey").
method(8,"getRawUserIDs()","org.bouncycastle.openpgp.PGPPublicKey").
method(8,"getUserAttributes()","org.bouncycastle.openpgp.PGPPublicKey").


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
