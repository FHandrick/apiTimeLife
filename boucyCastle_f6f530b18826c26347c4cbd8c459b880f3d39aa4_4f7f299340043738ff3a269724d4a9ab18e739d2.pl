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

method(3,"arrayContains(short[] a, short n)","org.bouncycastle.crypto.tls.TlsProtocol").
method(3,"arrayContains(int[] a, int n)","org.bouncycastle.crypto.tls.TlsProtocol").
method(8,"getGeneratedVersion()","org.bouncycastle.cms.SignerInfoGenerator").
method(3,"Builder(Map paramsMap)","org.bouncycastle.crypto.params.SkeinParameters.Builder").
method(3,"processCertificateVerify(ServerHandshakeState state, byte[] body, byte[] certificateVerifyHash)","org.bouncycastle.crypto.tls.DTLSServerProtocol").
method(8,"getGeneratedVersion()","org.bouncycastle.cms.SignerInfoGenerator").
method(3,"PublicKeyEncSessionPacket(long keyID, int algorithm, BigInteger[] data)","org.bouncycastle.bcpg.PublicKeyEncSessionPacket").
method(8,"processSessionInfo(byte[] encryptedSessionInfo)","org.bouncycastle.openpgp.operator.PublicKeyKeyEncryptionMethodGenerator").
method(3,"recoverSessionData(int keyAlgorithm, BigInteger[] secKeyData)","org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory").
method(3,"recoverSessionData(int keyAlgorithm, BigInteger[] secKeyData)","org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory").
method(8,"getEncSessionKey()","org.bouncycastle.bcpg.PublicKeyEncSessionPacket").
method(3,"createHash(int hashAlgorithm)","org.bouncycastle.crypto.tls.TlsUtils").
method(3,"cloneHash(int hashAlgorithm, Digest hash)","org.bouncycastle.crypto.tls.TlsUtils").
method(3,"getOIDForHashAlgorithm(int hashAlgorithm)","org.bouncycastle.crypto.tls.TlsUtils").
method(8,"getInstance(ASN1TaggedObject obj, boolean explicit)","org.bouncycastle.asn1.DEREnumerated").
method(3,"createCurve(Config builder)","org.bouncycastle.math.ec.ECCurve").
method(3,"createCurve(Config builder)","org.bouncycastle.math.ec.ECCurve.Fp").
method(2,"createPoint(BigInteger, BigInteger, boolean)","createRawPoint(ECFieldElement, ECFieldElement, boolean)","org.bouncycastle.math.ec.ECCurve.Fp").
method(2,"createCurve(Config)","cloneCurve()","org.bouncycastle.math.ec.ECCurve.F2m").
method(3,"PEMWriter(Writer out, String provider)","org.bouncycastle.openssl.PEMWriter").
method(5,"writeObject(Object, String, char[], SecureRandom)","org.bouncycastle.openssl.PEMWriter").
method(3,"PKCS8Generator(PrivateKey key)","org.bouncycastle.openssl.PKCS8Generator").
method(3,"PKCS8Generator(PrivateKey key, ASN1ObjectIdentifier algorithm, String provider)","org.bouncycastle.openssl.PKCS8Generator").
method(3,"PKCS8Generator(PrivateKey key, ASN1ObjectIdentifier algorithm, Provider provider)","org.bouncycastle.openssl.PKCS8Generator").
method(3,"setSecureRandom(SecureRandom random)","org.bouncycastle.openssl.PKCS8Generator").
method(3,"setPassword(char[] password)","org.bouncycastle.openssl.PKCS8Generator").
method(3,"setIterationCount(int iterationCount)","org.bouncycastle.openssl.PKCS8Generator").
method(3,"generate(CMSProcessable content, String compressionOID)","org.bouncycastle.cms.CMSCompressedDataGenerator").
method(3,"getMacAlgorithmParameters(String provider)","org.bouncycastle.cms.CMSAuthenticatedDataParser").
method(3,"getMacAlgorithmParameters(Provider provider)","org.bouncycastle.cms.CMSAuthenticatedDataParser").
method(3,"CMSAuthenticatedDataStreamGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, String provider)","org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, Provider provider)","org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, int keySize, String provider)","org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, int keySize, Provider provider)","org.bouncycastle.cms.CMSAuthenticatedDataStreamGenerator").
method(3,"getEncryptionAlgorithmParameters(String provider)","org.bouncycastle.cms.CMSEnvelopedData").
method(3,"getEncryptionAlgorithmParameters(Provider provider)","org.bouncycastle.cms.CMSEnvelopedData").
method(3,"getContentInfo()","org.bouncycastle.cms.CMSEnvelopedData").
method(3,"getKeyEncryptionAlgorithmParameters(String provider)","org.bouncycastle.cms.RecipientInformation").
method(3,"getKeyEncryptionAlgorithmParameters(Provider provider)","org.bouncycastle.cms.RecipientInformation").
method(3,"getContent(Key key, String provider)","org.bouncycastle.cms.RecipientInformation").
method(3,"getContent(Key key, Provider provider)","org.bouncycastle.cms.RecipientInformation").
method(3,"getContentStream(Key key, String provider)","org.bouncycastle.cms.RecipientInformation").
method(3,"getContentStream(Key key, Provider provider)","org.bouncycastle.cms.RecipientInformation").
method(3,"getContentStream(Key key, String prov)","org.bouncycastle.cms.KeyTransRecipientInformation").
method(3,"getContentStream(Key key, Provider prov)","org.bouncycastle.cms.KeyTransRecipientInformation").
method(3,"CMSSignedDataStreamGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, String sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, Provider sigProvider, Provider digProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGenerator, CMSAttributeTableGenerator unsignedAttrGenerator, Provider sigProvider, Provider digProvider)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"open(OutputStream out, String eContentType, boolean encapsulate)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"open(OutputStream out, String eContentType, boolean encapsulate, OutputStream dataOutputStream)","org.bouncycastle.cms.CMSSignedDataStreamGenerator").
method(3,"getContentStream(Key key, String prov)","org.bouncycastle.cms.KeyAgreeRecipientInformation").
method(3,"getContentStream(Key key, Provider prov)","org.bouncycastle.cms.KeyAgreeRecipientInformation").
method(3,"getMacAlgorithmParameters(String provider)","org.bouncycastle.cms.CMSAuthenticatedData").
method(3,"getMacAlgorithmParameters(Provider provider)","org.bouncycastle.cms.CMSAuthenticatedData").
method(3,"getKeyDerivationAlgParameters(String provider)","org.bouncycastle.cms.PasswordRecipientInformation").
method(3,"getKeyDerivationAlgParameters(Provider provider)","org.bouncycastle.cms.PasswordRecipientInformation").
method(3,"getContentStream(Key key, String prov)","org.bouncycastle.cms.PasswordRecipientInformation").
method(3,"getContentStream(Key key, Provider prov)","org.bouncycastle.cms.PasswordRecipientInformation").
method(3,"CMSEnvelopedGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKeyTransRecipient(X509Certificate cert)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKeyTransRecipient(PublicKey key, byte[] subKeyId)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKEKRecipient(SecretKey key, byte[] keyIdentifier)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKEKRecipient(SecretKey key, KEKIdentifier kekIdentifier)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addPasswordRecipient(CMSPBEKey pbeKey, String kekAlgorithmOid)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKeyAgreementRecipient(String agreementAlgorithm, PrivateKey senderPrivateKey, PublicKey senderPublicKey, X509Certificate recipientCert, String cekWrapAlgorithm, String provider)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKeyAgreementRecipient(String agreementAlgorithm, PrivateKey senderPrivateKey, PublicKey senderPublicKey, X509Certificate recipientCert, String cekWrapAlgorithm, Provider provider)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKeyAgreementRecipients(String agreementAlgorithm, PrivateKey senderPrivateKey, PublicKey senderPublicKey, Collection recipientCerts, String cekWrapAlgorithm, String provider)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"addKeyAgreementRecipients(String agreementAlgorithm, PrivateKey senderPrivateKey, PublicKey senderPublicKey, Collection recipientCerts, String cekWrapAlgorithm, Provider provider)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"getAlgorithmIdentifier(String encryptionOID, AlgorithmParameters params)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"convertOldRecipients(SecureRandom rand, Provider provider)","org.bouncycastle.cms.CMSEnvelopedGenerator").
method(3,"CMSAuthenticatedDataGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSAuthenticatedDataGenerator").
method(3,"generate(CMSProcessable content, String macOID, String provider)","org.bouncycastle.cms.CMSAuthenticatedDataGenerator").
method(3,"generate(CMSProcessable content, String encryptionOID, Provider provider)","org.bouncycastle.cms.CMSAuthenticatedDataGenerator").
method(3,"verify(PublicKey key, String sigProvider)","org.bouncycastle.cms.SignerInformation").
method(3,"verify(PublicKey key, Provider sigProvider)","org.bouncycastle.cms.SignerInformation").
method(3,"verify(X509Certificate cert, String sigProvider)","org.bouncycastle.cms.SignerInformation").
method(3,"verify(X509Certificate cert, Provider sigProvider)","org.bouncycastle.cms.SignerInformation").
method(3,"toSignerInfo()","org.bouncycastle.cms.SignerInformation").
method(3,"CMSAuthenticatedGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSAuthenticatedGenerator").
method(3,"open(OutputStream out, String compressionOID)","org.bouncycastle.cms.CMSCompressedDataStreamGenerator").
method(3,"open(OutputStream out, String contentOID, String compressionOID)","org.bouncycastle.cms.CMSCompressedDataStreamGenerator").
method(3,"CMSEnvelopedDataGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSEnvelopedDataGenerator").
method(3,"generate(CMSProcessable content, String encryptionOID, String provider)","org.bouncycastle.cms.CMSEnvelopedDataGenerator").
method(3,"generate(CMSProcessable content, String encryptionOID, Provider provider)","org.bouncycastle.cms.CMSEnvelopedDataGenerator").
method(3,"generate(CMSProcessable content, String encryptionOID, int keySize, String provider)","org.bouncycastle.cms.CMSEnvelopedDataGenerator").
method(3,"generate(CMSProcessable content, String encryptionOID, int keySize, Provider provider)","org.bouncycastle.cms.CMSEnvelopedDataGenerator").
method(3,"getContentStream(Key key, String prov)","org.bouncycastle.cms.KEKRecipientInformation").
method(3,"getContentStream(Key key, Provider prov)","org.bouncycastle.cms.KEKRecipientInformation").
method(3,"CMSEnvelopedDataStreamGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, String provider)","org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, Provider provider)","org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, int keySize, String provider)","org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator").
method(3,"open(OutputStream out, String encryptionOID, int keySize, Provider provider)","org.bouncycastle.cms.CMSEnvelopedDataStreamGenerator").
method(3,"getCertificatesAndCRLs(String type, String provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getCertificatesAndCRLs(String type, Provider provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getContentInfo()","org.bouncycastle.cms.CMSSignedData").
method(3,"replaceCertificatesAndCRLs(CMSSignedData signedData, CertStore certsAndCrls)","org.bouncycastle.cms.CMSSignedData").
method(3,"CMSSignedDataParser(byte[] sigBlock)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"CMSSignedDataParser(CMSTypedStream signedContent, byte[] sigBlock)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"CMSSignedDataParser(InputStream sigData)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"CMSSignedDataParser(CMSTypedStream signedContent, InputStream sigData)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getCertificatesAndCRLs(String type, String provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getCertificatesAndCRLs(String type, Provider provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"replaceCertificatesAndCRLs(InputStream original, CertStore certsAndCrls, OutputStream out)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getEncryptionAlgorithmParameters(String provider)","org.bouncycastle.cms.CMSEnvelopedDataParser").
method(3,"getEncryptionAlgorithmParameters(Provider provider)","org.bouncycastle.cms.CMSEnvelopedDataParser").
method(3,"CMSSignedGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSSignedGenerator").
method(3,"getEncOID(PrivateKey key, String digestOID)","org.bouncycastle.cms.CMSSignedGenerator").
method(3,"getAttributeSet(AttributeTable attr)","org.bouncycastle.cms.CMSSignedGenerator").
method(3,"addCertificatesAndCRLs(CertStore certStore)","org.bouncycastle.cms.CMSSignedGenerator").
method(3,"getContent()","org.bouncycastle.cms.CMSCompressedDataParser").
method(3,"CMSSignedDataGenerator(SecureRandom rand)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, CMSAttributeTableGenerator signedAttrGen, CMSAttributeTableGenerator unsignedAttrGen)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGen, CMSAttributeTableGenerator unsignedAttrGen)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String digestOID, CMSAttributeTableGenerator signedAttrGen, CMSAttributeTableGenerator unsignedAttrGen)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"addSigner(PrivateKey key, byte[] subjectKeyID, String encryptionOID, String digestOID, CMSAttributeTableGenerator signedAttrGen, CMSAttributeTableGenerator unsignedAttrGen)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(CMSProcessable content, String sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(CMSProcessable content, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(String eContentType, CMSProcessable content, boolean encapsulate, String sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(String eContentType, CMSProcessable content, boolean encapsulate, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(String eContentType, CMSProcessable content, boolean encapsulate, String sigProvider, boolean addDefaultAttributes)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(String eContentType, final CMSProcessable content, boolean encapsulate, Provider sigProvider, boolean addDefaultAttributes)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(CMSProcessable content, boolean encapsulate, String sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generate(CMSProcessable content, boolean encapsulate, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generateCounterSigners(SignerInformation signer, Provider sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"generateCounterSigners(SignerInformation signer, String sigProvider)","org.bouncycastle.cms.CMSSignedDataGenerator").
method(3,"getContent()","org.bouncycastle.cms.CMSCompressedData").
method(3,"getContent(int limit)","org.bouncycastle.cms.CMSCompressedData").
method(3,"getContentInfo()","org.bouncycastle.cms.CMSCompressedData").
method(3,"TimeStampTokenGenerator(DigestCalculator sha1DigestCalculator, final SignerInfoGenerator signerInfoGen, ASN1ObjectIdentifier tsaPolicy)","org.bouncycastle.tsp.TimeStampTokenGenerator").
method(3,"TimeStampTokenGenerator(final SignerInfoGenerator signerInfoGen, ASN1ObjectIdentifier tsaPolicy)","org.bouncycastle.tsp.TimeStampTokenGenerator").
method(3,"TimeStampTokenGenerator(PrivateKey key, X509Certificate cert, String digestOID, String tsaPolicyOID)","org.bouncycastle.tsp.TimeStampTokenGenerator").
method(3,"TimeStampTokenGenerator(PrivateKey key, X509Certificate cert, ASN1ObjectIdentifier digestOID, String tsaPolicyOID)","org.bouncycastle.tsp.TimeStampTokenGenerator").
method(3,"TimeStampTokenGenerator(PrivateKey key, X509Certificate cert, String digestOID, String tsaPolicyOID, AttributeTable signedAttr, AttributeTable unsignedAttr)","org.bouncycastle.tsp.TimeStampTokenGenerator").
method(3,"setCertificatesAndCRLs(CertStore certificates)","org.bouncycastle.tsp.TimeStampTokenGenerator").
method(3,"generate(TimeStampRequest request, BigInteger serialNumber, Date genTime, String provider)","org.bouncycastle.tsp.TimeStampTokenGenerator").
method(3,"generate(TimeStampRequest request, BigInteger serialNumber, Date genTime, String provider)","org.bouncycastle.tsp.TimeStampResponseGenerator").
method(3,"validate(Set algorithms, Set policies, Set extensions, String provider)","org.bouncycastle.tsp.TimeStampRequest").
method(3,"getExtensionValue(String oid)","org.bouncycastle.tsp.TimeStampRequest").
method(3,"getSignatureTimestamps(SignerInformation signerInfo, Provider provider)","org.bouncycastle.tsp.TSPUtil").
method(3,"validateCertificate(X509Certificate cert)","org.bouncycastle.tsp.TSPUtil").
method(3,"getCertificatesAndCRLs(String type, String provider)","org.bouncycastle.tsp.TimeStampToken").
method(3,"validate(X509Certificate cert, String provider)","org.bouncycastle.tsp.TimeStampToken").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"addSigner(PrivateKey key, X509Certificate cert, String encryptionOID, String digestOID, AttributeTable signedAttr, AttributeTable unsignedAttr)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"addCertificatesAndCRLs(CertStore certStore)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"addAttributeCertificates(X509Store store)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generate(MimeBodyPart content, String sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generate(MimeBodyPart content, Provider sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generate(MimeMessage message, String sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generate(MimeMessage message, Provider sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generateEncapsulated(MimeBodyPart content, String sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generateEncapsulated(MimeBodyPart content, Provider sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generateEncapsulated(MimeMessage message, String sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generateEncapsulated(MimeMessage message, Provider sigProvider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generateCertificateManagement(String provider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"generateCertificateManagement(Provider provider)","org.bouncycastle.mail.smime.SMIMESignedGenerator").
method(3,"SMIMESignedParser(MimeMultipart message)","org.bouncycastle.mail.smime.SMIMESignedParser").
method(3,"SMIMESignedParser(MimeMultipart message, File backingFile)","org.bouncycastle.mail.smime.SMIMESignedParser").
method(3,"SMIMESignedParser(MimeMultipart message, String defaultContentTransferEncoding)","org.bouncycastle.mail.smime.SMIMESignedParser").
method(3,"SMIMESignedParser(MimeMultipart message, String defaultContentTransferEncoding, File backingFile)","org.bouncycastle.mail.smime.SMIMESignedParser").
method(3,"SMIMESignedParser(Part message)","org.bouncycastle.mail.smime.SMIMESignedParser").
method(3,"SMIMESignedParser(Part message, File file)","org.bouncycastle.mail.smime.SMIMESignedParser").
method(3,"generate(MimeBodyPart content, String compressionOID)","org.bouncycastle.mail.smime.SMIMECompressedGenerator").
method(3,"generate(MimeMessage message, String compressionOID)","org.bouncycastle.mail.smime.SMIMECompressedGenerator").
method(3,"addKeyTransRecipient(X509Certificate cert)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"addKeyTransRecipient(PublicKey key, byte[] subKeyId)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"addKEKRecipient(SecretKey key, byte[] keyIdentifier)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"addKeyAgreementRecipient(String agreementAlgorithm, PrivateKey senderPrivateKey, PublicKey senderPublicKey, X509Certificate recipientCert, String cekWrapAlgorithm, String provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"addKeyAgreementRecipient(String agreementAlgorithm, PrivateKey senderPrivateKey, PublicKey senderPublicKey, X509Certificate recipientCert, String cekWrapAlgorithm, Provider provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeBodyPart content, String encryptionOID, String provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeBodyPart content, String encryptionOID, Provider provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeMessage message, String encryptionOID, String provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeMessage message, String encryptionOID, Provider provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeBodyPart content, String encryptionOID, int keySize, String provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeBodyPart content, String encryptionOID, int keySize, Provider provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeMessage message, String encryptionOID, int keySize, String provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(3,"generate(MimeMessage message, String encryptionOID, int keySize, Provider provider)","org.bouncycastle.mail.smime.SMIMEEnvelopedGenerator").
method(2,"assertNormalized()","checkNormalized()","org.bouncycastle.math.ec.ECPoint").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.MontgomeryLadderMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.NafL2RMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.ZSignedDigitR2LMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.WNafL2RMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.ReferenceMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.MixedNafR2LMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.ZSignedDigitL2RMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.WTauNafMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.DoubleAddMultiplier").
method(2,"multiply(ECPoint, BigInteger, PreCompInfo)","multiplyPositive(ECPoint, BigInteger)","org.bouncycastle.math.ec.NafR2LMultiplier").
method(3,"precompute(ECPoint p, PreCompInfo preCompInfo, int width)","org.bouncycastle.math.ec.WNafUtil").
method(3,"generateWindowNaf(byte width, BigInteger k)","org.bouncycastle.math.ec.WNafUtil").
method(3,"windowNaf(byte width, BigInteger k)","org.bouncycastle.math.ec.WNafL2RMultiplier").
method(9,"Fp(ECCurve curve, ECFieldElement x, ECFieldElement y, ECFieldElement[] zs)","org.bouncycastle.math.ec.ECPoint.Fp").
method(2,"getZ(int)","getZCoord(int)","org.bouncycastle.math.ec.ECPoint").
method(2,"getZs()","getZCoords()","org.bouncycastle.math.ec.ECPoint").
method(3,"hashCode(BigInteger[] data)","org.bouncycastle.util.Arrays").
method(3,"areEqual(BigInteger[] a, BigInteger[] b)","org.bouncycastle.util.Arrays").
method(9,"Fp(BigInteger q, BigInteger r, BigInteger x)","org.bouncycastle.math.ec.ECCurve.Fp").
method(3,"failWithError(short alertLevel, short alertDescription)","org.bouncycastle.crypto.tls.TlsProtocol").
method(1,"safeDecryptPreMasterSecret(TlsContext, TlsEncryptionCredentials, byte[])","org-bouncycastle-crypto-tls-tlsrsakeyexchange,org.bouncycastle.crypto.tls.TlsRSAUtils").
method(3,"getSbox()","org.bouncycastle.jce.spec.GOST28147ParameterSpec").
method(3,"getIV()","org.bouncycastle.jce.spec.GOST28147ParameterSpec").
method(3,"getAlgorithm()","org.bouncycastle.jce.spec.RepeatedSecretKeySpec").
method(3,"getFormat()","org.bouncycastle.jce.spec.RepeatedSecretKeySpec").
method(3,"getEncoded()","org.bouncycastle.jce.spec.RepeatedSecretKeySpec").
method(3,"getEncoded(boolean compressed)","org.bouncycastle.math.ec.ECPoint.Fp").
method(3,"getEncoded(boolean compressed)","org.bouncycastle.math.ec.ECPoint.F2m").
method(2,"parseHelloVerifyRequest(TlsContext, byte[])","processHelloVerifyRequest(ClientHandshakeState, byte[])","org.bouncycastle.crypto.tls.DTLSClientProtocol").
method(3,"initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters)","org.bouncycastle.crypto.tls.TlsSRPKeyExchange").
method(3,"initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters)","org.bouncycastle.crypto.tls.TlsDHEKeyExchange").
method(3,"initVerifyer(TlsSigner tlsSigner, SecurityParameters securityParameters)","org.bouncycastle.crypto.tls.TlsECDHEKeyExchange").
method(3,"generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1)","org.bouncycastle.crypto.tls.TlsRSASigner").
method(3,"verifyRawSignature(byte[] sigBytes, AsymmetricKeyParameter publicKey, byte[] md5AndSha1)","org.bouncycastle.crypto.tls.TlsRSASigner").
method(3,"makeSigner(SignatureAndHashAlgorithm algorithm, boolean forSigning, CipherParameters cp)","org.bouncycastle.crypto.tls.TlsRSASigner").
method(3,"makeSigner(Digest d, boolean forSigning, CipherParameters cp)","org.bouncycastle.crypto.tls.TlsRSASigner").
method(3,"generateRawSignature(AsymmetricKeyParameter privateKey, byte[] md5AndSha1)","org.bouncycastle.crypto.tls.TlsDSASigner").
method(1,"verifyRawSignature(SignatureAndHashAlgorithm, byte[], AsymmetricKeyParameter, byte[])","org-bouncycastle-crypto-tls-tlsdsasigner,org.bouncycastle.crypto.tls.TlsRSASigner").
method(3,"makeSigner(SignatureAndHashAlgorithm algorithm, boolean forSigning, CipherParameters cp)","org.bouncycastle.crypto.tls.TlsDSASigner").
method(3,"makeSigner(Digest d, boolean forSigning, CipherParameters cp)","org.bouncycastle.crypto.tls.TlsDSASigner").
method(3,"createSigner(AsymmetricKeyParameter privateKey)","org.bouncycastle.crypto.tls.TlsRSASigner").
method(3,"createVerifyer(AsymmetricKeyParameter publicKey)","org.bouncycastle.crypto.tls.TlsRSASigner").
method(3,"createSigner(AsymmetricKeyParameter privateKey)","org.bouncycastle.crypto.tls.TlsDSASigner").
method(3,"createVerifyer(AsymmetricKeyParameter publicKey)","org.bouncycastle.crypto.tls.TlsDSASigner").
method(3,"getDigest()","org.bouncycastle.crypto.DerivationFunction").
method(8,"processMaxFragmentLengthExtension(Hashtable clientExtensions, Hashtable serverExtensions, short alertDescription)","org.bouncycastle.crypto.tls.TlsProtocol").
method(3,"getClientExtensions()","org.bouncycastle.crypto.tls.DefaultTlsClient").
method(3,"processServerExtensions(Hashtable serverExtensions)","org.bouncycastle.crypto.tls.DefaultTlsClient").
method(3,"TlsPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, DHParameters dhParameters, TlsPSKIdentity pskIdentity)","org.bouncycastle.crypto.tls.TlsPSKKeyExchange").
method(3,"SessionParameters(Certificate peerCertificate, int cipherSuite, short compressionAlgorithm, byte[] masterSecret)","org.bouncycastle.crypto.tls.SessionParameters").
method(3,"SessionParameters(Certificate peerCertificate, SecurityParameters securityParameters)","org.bouncycastle.crypto.tls.SessionParameters").
method(1,"importSession(byte[], SessionParameters)","org-bouncycastle-crypto-tls-tlsprotocol,org.bouncycastle.crypto.tls.TlsUtils").
method(3,"SessionParameters(int cipherSuite, short compressionAlgorithm, byte[] masterSecret)","org.bouncycastle.crypto.tls.SessionParameters").
method(3,"SessionParameters(SecurityParameters securityParameters)","org.bouncycastle.crypto.tls.SessionParameters").
method(5,"connect(TlsClient, TlsSession)","org.bouncycastle.crypto.tls.TlsClientProtocol").
method(3,"handleChangeCipherSpecMessage()","org.bouncycastle.crypto.tls.TlsClientProtocol").
method(3,"handleChangeCipherSpecMessage()","org.bouncycastle.crypto.tls.TlsServerProtocol").
method(3,"evaluateStatusRequestExtension(Hashtable serverExtensions, short alertDescription)","org.bouncycastle.crypto.tls.DTLSProtocol").
method(3,"processServerStatusExtension(Hashtable serverExtensions, short alertDescription)","org.bouncycastle.crypto.tls.TlsProtocol").
method(9,"serverHandshake(ServerHandshakeState state, DTLSRecordLayer recordLayer)","org.bouncycastle.crypto.tls.DTLSServerProtocol").
method(7,"writeVersion(ProtocolVersion version, byte[] buf, int offset)","org.bouncycastle.crypto.tls.TlsUtils").
method(3,"CertificateRequest(short[] certificateTypes, Vector certificateAuthorities)","org.bouncycastle.crypto.tls.CertificateRequest").
method(3,"parse(InputStream input)","org.bouncycastle.crypto.tls.CertificateRequest").
method(3,"sendCertificateVerifyMessage(byte[] data)","org.bouncycastle.crypto.tls.TlsClientProtocol").
method(3,"generateCertificateVerify(ClientHandshakeState state, byte[] signature)","org.bouncycastle.crypto.tls.DTLSClientProtocol").
method(1,"areCompatibleParameters(DHParameters, DHParameters)","org-bouncycastle-crypto-tls-tlsdhkeyexchange,org.bouncycastle.crypto.tls.TlsDHUtils").
method(3,"calculateDHBasicAgreement(DHPublicKeyParameters publicKey, DHPrivateKeyParameters privateKey)","org.bouncycastle.crypto.tls.TlsDHKeyExchange").
method(3,"generateDHKeyPair(DHParameters dhParams)","org.bouncycastle.crypto.tls.TlsDHKeyExchange").
method(3,"validateDHPublicKey(DHPublicKeyParameters key)","org.bouncycastle.crypto.tls.TlsDHKeyExchange").
method(3,"TlsPSKKeyExchange(int keyExchange, Vector supportedSignatureAlgorithms, TlsPSKIdentity pskIdentity)","org.bouncycastle.crypto.tls.TlsPSKKeyExchange").
method(7,"generateOtherSecret(int pskLength)","org.bouncycastle.crypto.tls.TlsPSKKeyExchange").
method(3,"ECDSAPublicBCPGKey(ECPoint point, ASN1ObjectIdentifier oid)","org.bouncycastle.bcpg.ECDSAPublicBCPGKey").
method(3,"ECPublicBCPGKey(ECPoint point, ASN1ObjectIdentifier oid)","org.bouncycastle.bcpg.ECPublicBCPGKey").
method(3,"ECDHPublicBCPGKey(ECPoint point, ASN1ObjectIdentifier oid, int hashAlgorithm, int symmetricKeyAlgorithm)","org.bouncycastle.bcpg.ECDHPublicBCPGKey").
method(7,"ECDSAPublicBCPGKey(BCPGInputStream in)","org.bouncycastle.bcpg.ECDSAPublicBCPGKey").
method(7,"ECPublicBCPGKey(BCPGInputStream in)","org.bouncycastle.bcpg.ECPublicBCPGKey").
method(7,"ECPublicBCPGKey(BigInteger encodedPoint, ASN1ObjectIdentifier oid)","org.bouncycastle.bcpg.ECPublicBCPGKey").
method(7,"readBytesOfEncodedLength(BCPGInputStream in)","org.bouncycastle.bcpg.ECPublicBCPGKey").
method(7,"ECDHPublicBCPGKey(BCPGInputStream in)","org.bouncycastle.bcpg.ECDHPublicBCPGKey").
method(7,"ECDHPublicBCPGKey(ECPoint point, ASN1ObjectIdentifier oid, int hashAlgorithm, int symmetricKeyAlgorithm)","org.bouncycastle.bcpg.ECDHPublicBCPGKey").
method(7,"getCertificateRequest()","org.bouncycastle.crypto.tls.AbstractTlsServer").
method(8,"processServerCertificate(ClientHandshakeState state, byte[] body)","org.bouncycastle.crypto.tls.DTLSClientProtocol").
method(2,"addOCSPStatusRequestExtension(Hashtable, OCSPStatusRequest)","addStatusRequestExtension(Hashtable, CertificateStatusRequest)","org.bouncycastle.crypto.tls.TlsExtensionsUtils").
method(2,"createOCSPStatusRequestExtension(OCSPStatusRequest)","createStatusRequestExtension(CertificateStatusRequest)","org.bouncycastle.crypto.tls.TlsExtensionsUtils").
method(3,"CRLValidation(Store crls)","org.bouncycastle.cert.path.validations.CRLValidation").
method(3,"CertPathValidationResult()","org.bouncycastle.cert.path.CertPathValidationResult").
method(3,"CertPathValidationResult(int certIndex, int ruleIndex, CertPathValidationException cause)","org.bouncycastle.cert.path.CertPathValidationResult").
method(3,"CertPathValidationResult(int[] certIndexes, int[] ruleIndexes, CertPathValidationException[] cause)","org.bouncycastle.cert.path.CertPathValidationResult").
method(3,"validate(int index, X509CertificateHolder certificate)","org.bouncycastle.cert.path.validations.BasicConstraintsValidation").
method(3,"validate(int index, X509CertificateHolder certificate)","org.bouncycastle.cert.path.validations.ParentCertIssuedValidation").
method(3,"validate(int index, X509CertificateHolder certificate)","org.bouncycastle.cert.path.validations.CRLValidation").
method(3,"validate(int index, X509CertificateHolder certificate)","org.bouncycastle.cert.path.CertPathValidation").
method(7,"getAlgorithmIdentifier(ASN1ObjectIdentifier algId, AlgorithmParameters parameters)","org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter").
method(7,"getAlgorithmIdentifier(ASN1ObjectIdentifier algorithm, AlgorithmParameterSpec algorithmSpec)","org.bouncycastle.operator.jcajce.JcaAlgorithmParametersConverter").
method(3,"getPRFAlgorithm(int ciphersuite)","org.bouncycastle.crypto.tls.TlsProtocol").
method(3,"JceAsymmetricKeyWrapper(PublicKey publicKey, AlgorithmParameterSpec algorithmParameterSpec)","org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper").
method(3,"JceAsymmetricKeyWrapper(X509Certificate certificate, AlgorithmParameterSpec algorithmParameterSpec)","org.bouncycastle.operator.jcajce.JceAsymmetricKeyWrapper").
method(3,"JceKeyTransRecipientInfoGenerator(X509Certificate recipientCert, AlgorithmParameterSpec parameterSpec)","org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator").
method(3,"JceKeyTransRecipientInfoGenerator(byte[] subjectKeyIdentifier, PublicKey publicKey, AlgorithmParameterSpec parameterSpec)","org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator").
method(9,"X9FieldID(ASN1Sequence seq)","org.bouncycastle.asn1.x9.X9FieldID").
method(3,"getAttributeCertificates(String type, String provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getAttributeCertificates(String type, Provider provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getCertificates(String type, String provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getCertificates(String type, Provider provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getCRLs(String type, String provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getCRLs(String type, Provider provider)","org.bouncycastle.cms.CMSSignedData").
method(3,"getAttributeCertificates(String type, String provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getAttributeCertificates(String type, Provider provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getCertificates(String type, String provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getCertificates(String type, Provider provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getCRLs(String type, String provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"getCRLs(String type, Provider provider)","org.bouncycastle.cms.CMSSignedDataParser").
method(3,"addAttributeCertificates(X509Store store)","org.bouncycastle.cms.CMSSignedGenerator").
method(3,"ECPrivateKey(BigInteger key, ASN1Object parameters)","org.bouncycastle.asn1.sec.ECPrivateKey").
method(3,"ECPrivateKey(BigInteger key, DERBitString publicKey, ASN1Object parameters)","org.bouncycastle.asn1.sec.ECPrivateKey").
method(3,"getEncoded()","org.bouncycastle.crypto.ec.ECPair").


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
