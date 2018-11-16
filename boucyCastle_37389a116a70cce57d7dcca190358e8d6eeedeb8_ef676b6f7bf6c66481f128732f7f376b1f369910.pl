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

method(3,"getPGPPublicKey(int algorithm, AsymmetricKeyParameter pubKey, Date time)","org.bouncycastle.openpgp.operator.bc.BcPGPKeyConverter").
method(3,"calculateDerivedKey(byte[] encodedPassword, AlgorithmIdentifier derivationAlgorithm, int keySize)","org.bouncycastle.cms.jcajce.JcePasswordRecipient").
method(3,"calculateDerivedKey(byte[] encodedPassword, AlgorithmIdentifier derivationAlgorithm, int keySize)","org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator").
method(9,"getBody()","org.bouncycastle.asn1.ASN1ObjectIdentifier").
method(7,"engineGenerateSecret(String algorithm)","org.bouncycastle.jcajce.provider.asymmetric.dh.KeyAgreementSpi").
method(3,"SignatureSubpacket(int type, boolean critical, byte[] data)","org.bouncycastle.bcpg.SignatureSubpacket").
method(3,"Features(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.Features").
method(3,"TrustSignature(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.TrustSignature").
method(3,"KeyExpirationTime(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.KeyExpirationTime").
method(3,"SignerUserID(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.SignerUserID").
method(3,"EmbeddedSignature(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.EmbeddedSignature").
method(3,"PreferredAlgorithms(int type, boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.PreferredAlgorithms").
method(3,"PrimaryUserID(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.PrimaryUserID").
method(3,"SignatureCreationTime(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.SignatureCreationTime").
method(3,"IssuerKeyID(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.IssuerKeyID").
method(3,"SignatureExpirationTime(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.SignatureExpirationTime").
method(3,"NotationData(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.NotationData").
method(3,"RevocationReason(boolean isCritical, byte[] data)","org.bouncycastle.bcpg.sig.RevocationReason").
method(3,"Exportable(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.Exportable").
method(3,"KeyFlags(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.KeyFlags").
method(3,"Revocable(boolean critical, byte[] data)","org.bouncycastle.bcpg.sig.Revocable").
method(3,"RevocationKey(boolean isCritical, byte[] data)","org.bouncycastle.bcpg.sig.RevocationKey").
method(9,"BCrypt()","org.bouncycastle.crypto.generators.BCrypt").
method(3,"KeyAgreementSpi(String kaAlgorithm, BasicAgreement agreement, DerivationFunction kdf, KeyMaterialGenerator kmGen)","org.bouncycastle.jcajce.provider.asymmetric.ec.KeyAgreementSpi").
method(3,"Blake2bDigest(int rounds)","org.bouncycastle.crypto.digests.Blake2bDigest").
method(2,"GetRoleDescription(int)","getRoleDescription(int)","org.bouncycastle.asn1.eac.CertificateHolderAuthorization").
method(2,"GetFlag(String)","getFlag(String)","org.bouncycastle.asn1.eac.CertificateHolderAuthorization").
method(3,"getDigestSize()","org.bouncycastle.crypto.digests.SHA3Digest").
method(3,"update(byte in)","org.bouncycastle.crypto.digests.SHA3Digest").
method(3,"update(byte[] in, int inOff, int len)","org.bouncycastle.crypto.digests.SHA3Digest").
method(3,"reset()","org.bouncycastle.crypto.digests.SHA3Digest").
method(3,"getByteLength()","org.bouncycastle.crypto.digests.SHA3Digest").
method(2,"getcrlId()","getCrlId()","org.bouncycastle.asn1.pkcs.CRLBag").
method(2,"getCRLValue()","getCrlValue()","org.bouncycastle.asn1.pkcs.CRLBag").
method(7,"build(byte[] messageBytes)","org.bouncycastle.dvcs.CPDRequestBuilder").
method(2,"toASN1Object()","toASN1Primitive()","org.bouncycastle.cert.ocsp.RespID").
method(2,"toASN1Object()","toASN1Primitive()","org.bouncycastle.cert.ocsp.CertificateID").
method(3,"toFlexiBigIntArray(int[] input)","org.bouncycastle.pqc.math.linearalgebra.IntUtils").
method(3,"floatLog(float param)","org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions").
method(3,"main(String[] args)","org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions").
method(9,"OtherInfo(ASN1Sequence seq)","org.bouncycastle.asn1.x9.OtherInfo").
method(9,"KeySpecificInfo(ASN1Sequence seq)","org.bouncycastle.asn1.x9.KeySpecificInfo").
method(3,"DomainParameters(ASN1Integer p, ASN1Integer g, ASN1Integer q, ASN1Integer j, ValidationParams validationParams)","org.bouncycastle.asn1.x9.DomainParameters").
method(9,"DHPublicKey(ASN1Integer y)","org.bouncycastle.asn1.x9.DHPublicKey").
method(8,"getY()","org.bouncycastle.asn1.x9.DHPublicKey").
method(9,"copy()","org.bouncycastle.util.Memoable").
method(9,"reset(Memoable other)","org.bouncycastle.util.Memoable").
method(3,"guessParameterSpec(IESEngine engine)","org.bouncycastle.jcajce.provider.asymmetric.util.IESUtil").
method(9,"BERGenerator(OutputStream out, int tagNo, boolean isExplicit)","org.bouncycastle.asn1.BERGenerator").
method(3,"getInstance(Object obj)","org.bouncycastle.asn1.DERApplicationSpecific").
method(3,"isConstructed()","org.bouncycastle.asn1.DERApplicationSpecific").
method(3,"getContents()","org.bouncycastle.asn1.DERApplicationSpecific").
method(3,"getApplicationTag()","org.bouncycastle.asn1.DERApplicationSpecific").
method(3,"getObject()","org.bouncycastle.asn1.DERApplicationSpecific").
method(3,"getObject(int derTagNo)","org.bouncycastle.asn1.DERApplicationSpecific").
method(3,"hashCode()","org.bouncycastle.asn1.DERApplicationSpecific").
method(3,"writeBERBody(InputStream contentStream)","org.bouncycastle.asn1.BERGenerator").
method(3,"encodeTag(DERApplicationSpecific spec)","org.bouncycastle.asn1.eac.EACTags").
method(3,"toASN1Primitive()","org.bouncycastle.asn1.cms.TimeStampedDataParser").
method(3,"getKey()","org.bouncycastle.crypto.params.RC2Parameters").
method(7,"engineGetEncoded()","org.bouncycastle.jcajce.provider.symmetric.IDEA.AlgParams").
method(7,"engineSetParameter(AlgorithmParameterSpec params)","org.bouncycastle.jcajce.provider.asymmetric.rsa.PSSSignatureSpi").
method(3,"getBaseParameters(ASN1ObjectIdentifier contentType, AlgorithmIdentifier digAlgId, byte[] hash)","org.bouncycastle.cms.CMSAuthenticatedGenerator").
method(7,"NetscapeCertRequest(String challenge, AlgorithmIdentifier signing_alg, PublicKey pub_key)","org.bouncycastle.jce.netscape.NetscapeCertRequest").
method(7,"getObjectParser(int tag, boolean isExplicit)","org.bouncycastle.asn1.ASN1TaggedObject").
method(9,"AuthEnvelopedData(ASN1Sequence seq)","org.bouncycastle.asn1.cms.AuthEnvelopedData").
method(3,"calculateDerivedKey(byte[] encodedPassword, AlgorithmIdentifier derivationAlgorithm, int keySize)","org.bouncycastle.cms.bc.BcPasswordRecipientInfoGenerator").
method(3,"calculateDerivedKey(byte[] encodedPassword, AlgorithmIdentifier derivationAlgorithm, int keySize)","org.bouncycastle.cms.bc.BcPasswordRecipient").
method(3,"calculateDerivedKey(byte[] encodedPassword, AlgorithmIdentifier derivationAlgorithm, int keySize)","org.bouncycastle.cms.jcajce.JcePasswordRecipient").
method(3,"calculateDerivedKey(byte[] encodedPassword, AlgorithmIdentifier derivationAlgorithm, int keySize)","org.bouncycastle.cms.jcajce.JcePasswordRecipientInfoGenerator").
method(3,"calculateDerivedKey(byte[] encodedPassword, AlgorithmIdentifier derivationAlgorithm, int keySize)","org.bouncycastle.cms.PasswordRecipientInfoGenerator").
method(3,"VOMSAttribute(X509AttributeCertificate ac)","org.bouncycastle.voms.VOMSAttribute").
method(8,"getAC()","org.bouncycastle.voms.VOMSAttribute").
method(7,"verify(PublicKey key, Provider sigProvider)","org.bouncycastle.jce.provider.X509CRLObject").
method(7,"verify(PublicKey key, Provider sigProvider)","org.bouncycastle.jce.provider.X509CertificateObject").
method(3,"AlgorithmIdentifier(String objectId)","org.bouncycastle.asn1.x509.AlgorithmIdentifier").
method(3,"getObjectId()","org.bouncycastle.asn1.x509.AlgorithmIdentifier").
method(9,"AlgorithmIdentifier(ASN1Sequence seq)","org.bouncycastle.asn1.x509.AlgorithmIdentifier").
method(3,"addCRLEntry(BigInteger userCertificateSerial, Date revocationDate, X509Extensions extensions)","org.bouncycastle.cert.X509v2CRLBuilder").
method(3,"addCRLEntry(BigInteger userCertificateSerial, Date revocationDate, X509Extensions extensions)","org.bouncycastle.cert.X509v2CRLBuilder").
method(9,"AuthenticatedData(ASN1Sequence seq)","org.bouncycastle.asn1.cms.AuthenticatedData").
method(3,"setPreComp(ECPoint.F2m[] preComp)","org.bouncycastle.math.ec.WTauNafPreCompInfo").
method(3,"addSimple(ECPoint.F2m b)","org.bouncycastle.math.ec.ECPoint.F2m").
method(3,"subtract(ECPoint b)","org.bouncycastle.math.ec.ECPoint.F2m").
method(3,"subtractSimple(ECPoint.F2m b)","org.bouncycastle.math.ec.ECPoint.F2m").
method(8,"getPreComp()","org.bouncycastle.math.ec.WTauNafPreCompInfo").
method(3,"evaluateMaxFragmentLengthExtension(Hashtable clientExtensions, Hashtable serverExtensions, short alertDescription)","org.bouncycastle.crypto.tls.DTLSProtocol").
method(3,"getCipher()","org.bouncycastle.crypto.tls.SRPTlsServer").
method(3,"getCipher()","org.bouncycastle.crypto.tls.SRPTlsClient").
method(3,"getCipher()","org.bouncycastle.crypto.tls.DefaultTlsClient").
method(3,"getCipher()","org.bouncycastle.crypto.tls.PSKTlsServer").
method(3,"getCipher()","org.bouncycastle.crypto.tls.PSKTlsClient").
method(3,"getCipher()","org.bouncycastle.crypto.tls.DefaultTlsServer").
method(7,"engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)","org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher").


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
