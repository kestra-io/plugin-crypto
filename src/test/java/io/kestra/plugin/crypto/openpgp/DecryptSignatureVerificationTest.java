package io.kestra.plugin.crypto.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.junit.jupiter.api.Test;

import com.devskiller.friendly_id.FriendlyId;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.storages.StorageInterface;
import io.kestra.core.tenant.TenantService;

import jakarta.inject.Inject;
import org.bouncycastle.openpgp.PGPException;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Reproduces https://github.com/kestra-io/plugin-crypto/issues/117: {@link Decrypt} silently
 * skipped OpenPGP signature verification instead of enforcing it.
 */
@KestraTest
class DecryptSignatureVerificationTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private StorageInterface storageInterface;

    private static String readResource(String name) throws Exception {
        return IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        DecryptSignatureVerificationTest.class.getClassLoader().getResource(name)
                    ).toURI()
                )
            ),
            StandardCharsets.US_ASCII
        );
    }

    private URI storeFile(byte[] content) throws Exception {
        return storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new ByteArrayInputStream(content)
        );
    }

    /**
     * Builds a valid PGP encrypted+signed message, computing the one-pass signature over
     * {@code signedContent} while writing {@code literalContent} as the literal data. The two
     * tests below either pass matching content (real happy path) or diverging content
     * (simulated tampering, must fail {@code sig.verify(...)}).
     */
    private static byte[] buildEncryptedMessage(
        String encryptionPublicKey,
        PGPSecretKey signingSecretKey,
        PGPPrivateKey signingPrivateKey,
        byte[] literalContent,
        byte[] signedContent
    ) throws Exception {
        AbstractPgp.addProvider();

        PGPPublicKeyRingCollection pubKeyRings;
        try (var pubKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(encryptionPublicKey.getBytes(StandardCharsets.UTF_8)))) {
            pubKeyRings = new PGPPublicKeyRingCollection(pubKeyIn, new JcaKeyFingerprintCalculator());
        }
        PGPPublicKey encryptionKey = pubKeyRings.getKeyRings().next().getPublicKey();

        var signerBuilder = new JcaPGPContentSignerBuilder(signingSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA256);
        var signatureGenerator = new PGPSignatureGenerator(signerBuilder, signingSecretKey.getPublicKey());
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingPrivateKey);
        signatureGenerator.update(signedContent);

        var byteOut = new ByteArrayOutputStream();
        try (
            OutputStream fileOut = byteOut;
            var armoredOut = new ArmoredOutputStream(fileOut)
        ) {
            var encryptor = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom());

            var encGen = new PGPEncryptedDataGenerator(encryptor);
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey));

            try (OutputStream encOut = encGen.open(armoredOut, new byte[4096])) {
                var comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                try (var compressedOut = comData.open(encOut)) {
                    signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

                    var literalGen = new PGPLiteralDataGenerator();
                    try (var literalOut = literalGen.open(compressedOut, PGPLiteralData.BINARY, "data", new Date(), new byte[4096])) {
                        literalOut.write(literalContent);
                    }

                    signatureGenerator.generate().encode(compressedOut);
                }
            }
        }

        return byteOut.toByteArray();
    }

    private static byte[] buildEncryptedMessageWithMismatchedSignature(
        String encryptionPublicKey,
        String signingSecretKeyArmored,
        char[] signingPassphrase,
        byte[] literalContent,
        byte[] signedContent
    ) throws Exception {
        AbstractPgp.addProvider();

        PGPSecretKeyRingCollection secretKeyRings;
        try (var privKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(signingSecretKeyArmored.getBytes(StandardCharsets.UTF_8)))) {
            secretKeyRings = new PGPSecretKeyRingCollection(privKeyIn, new JcaKeyFingerprintCalculator());
        }
        PGPSecretKey signingKey = secretKeyRings.getKeyRings().next().getSecretKey();
        PGPPrivateKey signingPrivateKey = signingKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(signingPassphrase));

        return buildEncryptedMessage(encryptionPublicKey, signingKey, signingPrivateKey, literalContent, signedContent);
    }

    /**
     * Generates a fresh OpenPGP key ring whose primary key only certifies (no user ID lives on
     * the signing subkey) and carries a dedicated signing subkey, mirroring the layout GPG
     * produces by default (`gpg --sign` signs with a signing subkey, not the primary key).
     */
    private record SubkeySigningMaterial(String armoredPublicKey, PGPSecretKey signingSecretKey, PGPPrivateKey signingPrivateKey) {
    }

    private static SubkeySigningMaterial buildKeyRingWithDedicatedSigningSubkey(String userId, char[] passphrase) throws Exception {
        AbstractPgp.addProvider();

        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        var primaryKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, (PGPAlgorithmParameters) null, keyPairGenerator.generateKeyPair(), new Date());
        var encryptionSubKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, (PGPAlgorithmParameters) null, keyPairGenerator.generateKeyPair(), new Date());
        var signingSubKeyPair = new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, (PGPAlgorithmParameters) null, keyPairGenerator.generateKeyPair(), new Date());

        var primarySubpackets = new PGPSignatureSubpacketGenerator();
        primarySubpackets.setKeyFlags(false, KeyFlags.CERTIFY_OTHER);

        var encryptionSubpackets = new PGPSignatureSubpacketGenerator();
        encryptionSubpackets.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        var signingSubpackets = new PGPSignatureSubpacketGenerator();
        signingSubpackets.setKeyFlags(false, KeyFlags.SIGN_DATA);

        var digestCalculatorProvider = new JcaPGPDigestCalculatorProviderBuilder().build();
        var sha1Calc = digestCalculatorProvider.get(HashAlgorithmTags.SHA1);
        var sha256Calc = digestCalculatorProvider.get(HashAlgorithmTags.SHA256);

        var keyEncryptor = new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, sha256Calc).build(passphrase);

        var keyRingGenerator = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primaryKeyPair,
            userId,
            sha1Calc,
            primarySubpackets.generate(),
            null,
            new JcaPGPContentSignerBuilder(primaryKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            keyEncryptor
        );

        keyRingGenerator.addSubKey(encryptionSubKeyPair, encryptionSubpackets.generate(), null);
        keyRingGenerator.addSubKey(signingSubKeyPair, signingSubpackets.generate(), null);

        PGPSecretKeyRing secretKeyRing = keyRingGenerator.generateSecretKeyRing();
        PGPPublicKeyRing publicKeyRing = keyRingGenerator.generatePublicKeyRing();

        PGPSecretKey signingSecretKey = secretKeyRing.getSecretKey(signingSubKeyPair.getKeyID());
        PGPPrivateKey signingPrivateKey = signingSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(passphrase));

        var byteOut = new ByteArrayOutputStream();
        try (var armoredOut = new ArmoredOutputStream(byteOut)) {
            publicKeyRing.encode(armoredOut);
        }

        return new SubkeySigningMaterial(byteOut.toString(StandardCharsets.US_ASCII), signingSecretKey, signingPrivateKey);
    }

    @Test
    void unsignedMessageRejectedWhenSignatureRequired() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");
        var helloPublic = readResource("pgp/hello-key.pub");

        var file = new File(Objects.requireNonNull(getClass().getClassLoader().getResource("application.yml")).toURI());
        var fileStorage = storeFile(IOUtils.toByteArray(new FileInputStream(file)));

        var encrypt = Encrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .key(Property.ofValue(contactPublic))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        var encryptOutput = encrypt.run(runContext);

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(encryptOutput.getUri().toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(helloPublic)))
            .build();

        assertThrows(PGPException.class, () -> decrypt.run(runContext));
    }

    @Test
    void wrongSignerRejected() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");
        var helloPrivate = readResource("pgp/hello-key.sec");
        var helloPublic = readResource("pgp/hello-key.pub");

        var file = new File(Objects.requireNonNull(getClass().getClassLoader().getResource("application.yml")).toURI());
        var fileStorage = storeFile(IOUtils.toByteArray(new FileInputStream(file)));

        var encrypt = Encrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .key(Property.ofValue(contactPublic))
            .signPublicKey(Property.ofValue(helloPublic))
            .signPrivateKey(Property.ofValue(helloPrivate))
            .signPassphrase(Property.ofValue("abc456"))
            .signUser(Property.ofValue("hello@kestra.io"))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        var encryptOutput = encrypt.run(runContext);

        // signUsersKey only contains the recipient's own key, never the actual signer (hello)
        var decrypt = Decrypt.builder()
            .from(Property.ofValue(encryptOutput.getUri().toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(contactPublic)))
            .build();

        assertThrows(PGPException.class, () -> decrypt.run(runContext));
    }

    @Test
    void tamperedSignatureRejected() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");
        var helloPrivate = readResource("pgp/hello-key.sec");
        var helloPublic = readResource("pgp/hello-key.pub");

        var tampered = buildEncryptedMessageWithMismatchedSignature(
            contactPublic,
            helloPrivate,
            "abc456".toCharArray(),
            "actual content".getBytes(StandardCharsets.UTF_8),
            "different signed content".getBytes(StandardCharsets.UTF_8)
        );

        var fileStorage = storeFile(tampered);

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(helloPublic)))
            .build();

        assertThrows(PGPException.class, () -> decrypt.run(runContext));
    }

    @Test
    void requiredSignerUsersMismatchRejected() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");
        var helloPrivate = readResource("pgp/hello-key.sec");
        var helloPublic = readResource("pgp/hello-key.pub");

        var file = new File(Objects.requireNonNull(getClass().getClassLoader().getResource("application.yml")).toURI());
        var fileStorage = storeFile(IOUtils.toByteArray(new FileInputStream(file)));

        var encrypt = Encrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .key(Property.ofValue(contactPublic))
            .signPublicKey(Property.ofValue(helloPublic))
            .signPrivateKey(Property.ofValue(helloPrivate))
            .signPassphrase(Property.ofValue("abc456"))
            .signUser(Property.ofValue("hello@kestra.io"))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        var encryptOutput = encrypt.run(runContext);

        // the signature itself and the signer key are both valid, but the caller only trusts
        // a different user id
        var decrypt = Decrypt.builder()
            .from(Property.ofValue(encryptOutput.getUri().toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(helloPublic)))
            .requiredSignerUsers(Property.ofValue(Collections.singletonList("someone-else@kestra.io")))
            .build();

        assertThrows(PGPException.class, () -> decrypt.run(runContext));
    }

    @Test
    void signedMessageWithMatchingSignerAndRequiredUserIsDecryptedAndContentMatches() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");
        var helloPrivate = readResource("pgp/hello-key.sec");
        var helloPublic = readResource("pgp/hello-key.pub");

        var plaintext = "Kestra crypto plugin signature verification test payload".getBytes(StandardCharsets.UTF_8);
        var fileStorage = storeFile(plaintext);

        var encrypt = Encrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .key(Property.ofValue(contactPublic))
            .signPublicKey(Property.ofValue(helloPublic))
            .signPrivateKey(Property.ofValue(helloPrivate))
            .signPassphrase(Property.ofValue("abc456"))
            .signUser(Property.ofValue("hello@kestra.io"))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        var encryptOutput = encrypt.run(runContext);

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(encryptOutput.getUri().toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(helloPublic)))
            .requiredSignerUsers(Property.ofValue(Collections.singletonList("hello@kestra.io")))
            .build();
        var decryptOutput = decrypt.run(runContext);

        assertArrayEquals(
            plaintext,
            IOUtils.toByteArray(storageInterface.get(TenantService.MAIN_TENANT, null, decryptOutput.getUri()))
        );
    }

    @Test
    void subkeySignedMessageAcceptedWhenRequiredUserMatchesPrimaryKeyUserId() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");

        var signerUserId = "Kestra Subkey Signer <subkey-signer@kestra.io>";
        var signerMaterial = buildKeyRingWithDedicatedSigningSubkey(signerUserId, "subkey-pass".toCharArray());

        var plaintext = "Signed with a dedicated signing subkey, not the primary key".getBytes(StandardCharsets.UTF_8);
        var message = buildEncryptedMessage(
            contactPublic,
            signerMaterial.signingSecretKey(),
            signerMaterial.signingPrivateKey(),
            plaintext,
            plaintext
        );

        var fileStorage = storeFile(message);

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(signerMaterial.armoredPublicKey())))
            .requiredSignerUsers(Property.ofValue(Collections.singletonList("subkey-signer@kestra.io")))
            .build();
        var decryptOutput = decrypt.run(runContext);

        assertArrayEquals(
            plaintext,
            IOUtils.toByteArray(storageInterface.get(TenantService.MAIN_TENANT, null, decryptOutput.getUri()))
        );
    }

    @Test
    void requiredSignerUsersRejectsSignerWhoseUserIdMerelyContainsTheRequiredIdentity() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");

        // a trusted key whose self-asserted user id embeds the required identity as a substring
        var signerUserId = "Not Hello <not-hello@kestra.io>";
        var signerMaterial = buildKeyRingWithDedicatedSigningSubkey(signerUserId, "subkey-pass".toCharArray());

        var plaintext = "Signed by an impostor whose user id contains the required email".getBytes(StandardCharsets.UTF_8);
        var message = buildEncryptedMessage(
            contactPublic,
            signerMaterial.signingSecretKey(),
            signerMaterial.signingPrivateKey(),
            plaintext,
            plaintext
        );

        var fileStorage = storeFile(message);

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(signerMaterial.armoredPublicKey())))
            .requiredSignerUsers(Property.ofValue(Collections.singletonList("hello@kestra.io")))
            .build();

        assertThrows(PGPException.class, () -> decrypt.run(runContext));
    }

    @Test
    void requiredSignerUsersAcceptsFullUserIdMatch() throws Exception {
        var runContext = runContextFactory.of();

        var contactPublic = readResource("pgp/contact-key.pub");
        var contactPrivate = readResource("pgp/contact-key.sec");

        var signerUserId = "Kestra Subkey Signer <subkey-signer@kestra.io>";
        var signerMaterial = buildKeyRingWithDedicatedSigningSubkey(signerUserId, "subkey-pass".toCharArray());

        var plaintext = "Signed by a key matched on its complete user id".getBytes(StandardCharsets.UTF_8);
        var message = buildEncryptedMessage(
            contactPublic,
            signerMaterial.signingSecretKey(),
            signerMaterial.signingPrivateKey(),
            plaintext,
            plaintext
        );

        var fileStorage = storeFile(message);

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(signerMaterial.armoredPublicKey())))
            .requiredSignerUsers(Property.ofValue(Collections.singletonList(signerUserId)))
            .build();
        var decryptOutput = decrypt.run(runContext);

        assertArrayEquals(
            plaintext,
            IOUtils.toByteArray(storageInterface.get(TenantService.MAIN_TENANT, null, decryptOutput.getUri()))
        );
    }

}
