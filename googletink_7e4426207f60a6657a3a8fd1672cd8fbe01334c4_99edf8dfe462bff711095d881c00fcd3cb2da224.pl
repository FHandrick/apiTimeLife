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

method(7,"build()","com.google.crypto.tink.util.KeysDownloader.Builder").
method(7,"build()","com.google.crypto.tink.apps.paymentmethodtoken.GooglePaymentsPublicKeysManager.Builder").
method(7,"build()","com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenSender.Builder").
method(7,"build()","com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenRecipient.Builder").
method(7,"build()","com.google.crypto.tink.apps.paymentmethodtoken.SenderIntermediateCertFactory.Builder").
method(7,"build()","com.google.crypto.tink.apps.webpush.WebPushHybridEncrypt.Builder").
method(7,"withRecipientPublicKey(final byte[] val)","com.google.crypto.tink.apps.webpush.WebPushHybridDecrypt.Builder").
method(7,"build()","com.google.crypto.tink.apps.webpush.WebPushHybridDecrypt.Builder").
method(7,"withRecipientPublicKey(final byte[] val)","com.google.crypto.tink.apps.webpush.WebPushHybridDecrypt.Builder").
method(7,"decode(String hex)","com.google.crypto.tink.subtle.Hex").
method(9,"unsealV2(final String sealedMessage)","com.google.crypto.tink.apps.paymentmethodtoken.PaymentMethodTokenRecipient").
method(7,"AesGcmJce(final byte[] key)","com.google.crypto.tink.subtle.AesGcmJce").
method(7,"validateAesKeySize(int sizeInBytes)","com.google.crypto.tink.subtle.Validators").
method(3,"AwsKmsAead(AWSKMS kmsClient)","com.google.crypto.tink.integration.awskms.AwsKmsAead").
method(3,"addVerifyingPublicKey(final int keyId, final String val)","com.google.crypto.tink.apps.rewardedads.RewardedAdsVerifier.Builder").
method(3,"addVerifyingPublicKey(final int keyId, final ECPublicKey val)","com.google.crypto.tink.apps.rewardedads.RewardedAdsVerifier.Builder").
method(7,"withRecipientPublicKey(final byte[] val)","com.google.crypto.tink.apps.webpush.WebPushHybridDecrypt.Builder").
method(2,"createAesGcmStreamingKeyTemplate(int, HashType, int, int)","createAesGcmHkdfStreamingKeyTemplate(int, HashType, int, int)","com.google.crypto.tink.streamingaead.StreamingAeadKeyTemplates").
method(3,"AesCmac(final byte[] key)","com.google.crypto.tink.subtle.AesCmac").
method(3,"addCatalogue(String catalogueName, Catalogue catalogue)","com.google.crypto.tink.Registry").
method(8,"getCatalogue(String catalogueName)","com.google.crypto.tink.Registry").
method(8,"getKeyManager(String typeUrl, String primitiveName, int minVersion)","com.google.crypto.tink.Catalogue").
method(7,"build()","com.google.crypto.tink.apps.rewardedads.RewardedAdsVerifier.Builder").
method(2,"rand(int)","randInt(int)","com.google.crypto.tink.subtle.Random").
method(7,"computeSharedSecret(byte[] privateKey, byte[] peersPublicValue)","com.google.crypto.tink.subtle.X25519").
method(7,"publicFromPrivate(byte[] privateKey)","com.google.crypto.tink.subtle.X25519").
method(7,"hybridEncryptWithXSalsa20Poly1305(final byte[] peerPublicKey)","com.google.crypto.tink.subtle.NaClCryptoBox").
method(7,"hybridEncryptWithChaCha20Poly1305(final byte[] peerPublicKey)","com.google.crypto.tink.subtle.NaClCryptoBox").
method(7,"hybridEncryptWithXChaCha20Poly1305(final byte[] peerPublicKey)","com.google.crypto.tink.subtle.NaClCryptoBox").
method(7,"getPublicKey(final byte[] privateKey)","com.google.crypto.tink.subtle.NaClCryptoBox").
method(2,"ecPointEncode(EllipticCurve, PointFormatType, ECPoint)","pointEncode(EllipticCurve, PointFormatType, ECPoint)","com.google.crypto.tink.subtle.EllipticCurves").
method(3,"AesCtrHmacStreaming(byte[] ikm, int keySizeInBytes, int tagSizeInBytes, int ciphertextSegmentSize, int firstSegmentOffset)","com.google.crypto.tink.subtle.AesCtrHmacStreaming").
method(3,"AesGcmHkdfStreaming(byte[] ikm, int keySizeInBytes, int ciphertextSegmentSize, int firstSegmentOffset)","com.google.crypto.tink.subtle.AesGcmHkdfStreaming").
method(2,"headerLength()","getHeaderLength()","com.google.crypto.tink.subtle.AesCtrHmacStreaming").
method(3,"newEncryptingChannel(WritableByteChannel ciphertextChannel, byte[] associatedData)","com.google.crypto.tink.subtle.AesCtrHmacStreaming").
method(3,"newDecryptingChannel(ReadableByteChannel ciphertextChannel, byte[] associatedData)","com.google.crypto.tink.subtle.AesCtrHmacStreaming").
method(3,"newSeekableDecryptingChannel(SeekableByteChannel ciphertextSource, byte[] associatedData)","com.google.crypto.tink.subtle.AesCtrHmacStreaming").
method(3,"newEncryptingChannel(WritableByteChannel ciphertextChannel, byte[] associatedData)","com.google.crypto.tink.subtle.AesGcmHkdfStreaming").
method(3,"newDecryptingChannel(ReadableByteChannel ciphertextChannel, byte[] associatedData)","com.google.crypto.tink.subtle.AesGcmHkdfStreaming").
method(3,"newSeekableDecryptingChannel(SeekableByteChannel ciphertextSource, byte[] associatedData)","com.google.crypto.tink.subtle.AesGcmHkdfStreaming").
method(3,"checkPublicKey(ECPublicKey key)","com.google.crypto.tink.subtle.EllipticCurves").
method(9,"checkPointOnCurve(ECPoint point, EllipticCurve ec)","com.google.crypto.tink.subtle.EllipticCurves").
method(7,"Ed25519Verify(final byte[] publicKey)","com.google.crypto.tink.subtle.Ed25519Verify").


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
