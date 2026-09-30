package io.kestra.plugin.crypto.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;
import java.util.Random;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.junit.jupiter.api.Test;

import com.devskiller.friendly_id.FriendlyId;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.storages.StorageInterface;
import io.kestra.core.tenant.TenantService;

import jakarta.inject.Inject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Reproduces https://github.com/kestra-io/plugin-crypto/issues/123: {@link Decrypt} never checked
 * the integrity of the encrypted container, so a modified ciphertext decrypted "successfully" to
 * corrupted output.
 */
@KestraTest
class DecryptIntegrityTest {
    private static final byte[] PLAINTEXT = "Kestra crypto plugin integrity test payload. ".repeat(40).getBytes(StandardCharsets.UTF_8);

    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private StorageInterface storageInterface;

    private static String readResource(String name) throws Exception {
        return IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        DecryptIntegrityTest.class.getClassLoader().getResource(name)
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
     * Builds an encrypted, unsigned and uncompressed binary message for the contact key, using the
     * given encryptor to pick the container type (SEIP v1, AEAD v5 or legacy SED).
     */
    private static byte[] encryptUnsigned(JcePGPDataEncryptorBuilder encryptor, byte[] content) throws Exception {
        AbstractPgp.addProvider();

        PGPPublicKeyRingCollection pubKeyRings;
        try (var pubKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(readResource("pgp/contact-key.pub").getBytes(StandardCharsets.UTF_8)))) {
            pubKeyRings = new PGPPublicKeyRingCollection(pubKeyIn, new JcaKeyFingerprintCalculator());
        }

        var encGen = new PGPEncryptedDataGenerator(encryptor.setSecureRandom(new SecureRandom()));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKeyRings.getKeyRings().next().getPublicKey()));

        var byteOut = new ByteArrayOutputStream();
        try (
            OutputStream encOut = encGen.open(byteOut, new byte[4096]);
            var literalOut = new PGPLiteralDataGenerator().open(encOut, PGPLiteralData.BINARY, "data", new Date(), new byte[4096])
        ) {
            literalOut.write(content);
        }

        return byteOut.toByteArray();
    }

    /**
     * Same as {@link #encryptUnsigned}, with a one-pass signature from the hello key around the
     * literal data.
     */
    private static byte[] encryptSigned(JcePGPDataEncryptorBuilder encryptor, byte[] content) throws Exception {
        AbstractPgp.addProvider();

        PGPPublicKeyRingCollection pubKeyRings;
        try (var pubKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(readResource("pgp/contact-key.pub").getBytes(StandardCharsets.UTF_8)))) {
            pubKeyRings = new PGPPublicKeyRingCollection(pubKeyIn, new JcaKeyFingerprintCalculator());
        }

        PGPSecretKeyRingCollection secretKeyRings;
        try (var secretKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(readResource("pgp/hello-key.sec").getBytes(StandardCharsets.UTF_8)))) {
            secretKeyRings = new PGPSecretKeyRingCollection(secretKeyIn, new JcaKeyFingerprintCalculator());
        }
        PGPSecretKey signingKey = secretKeyRings.getKeyRings().next().getSecretKey();
        PGPPrivateKey signingPrivateKey = signingKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build("abc456".toCharArray()));

        var signatureGenerator = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(signingKey.getPublicKey().getAlgorithm(), PGPUtil.SHA256),
            signingKey.getPublicKey()
        );
        signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingPrivateKey);
        signatureGenerator.update(content);

        var encGen = new PGPEncryptedDataGenerator(encryptor.setSecureRandom(new SecureRandom()));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(pubKeyRings.getKeyRings().next().getPublicKey()));

        var byteOut = new ByteArrayOutputStream();
        try (OutputStream encOut = encGen.open(byteOut, new byte[4096])) {
            signatureGenerator.generateOnePassVersion(false).encode(encOut);
            try (var literalOut = new PGPLiteralDataGenerator().open(encOut, PGPLiteralData.BINARY, "data", new Date(), new byte[4096])) {
                literalOut.write(content);
            }
            signatureGenerator.generate().encode(encOut);
        }

        return byteOut.toByteArray();
    }

    private static JcePGPDataEncryptorBuilder seip() {
        return new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(true);
    }

    private byte[] decrypt(byte[] message) throws Exception {
        var decrypt = Decrypt.builder()
            .from(Property.ofValue(storeFile(message).toString()))
            .privateKey(Property.ofValue(readResource("pgp/contact-key.sec")))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .build();
        var output = decrypt.run(runContextFactory.of());

        return IOUtils.toByteArray(storageInterface.get(TenantService.MAIN_TENANT, null, output.getUri()));
    }

    @Test
    void untamperedUnsignedMessageDecrypts() throws Exception {
        assertArrayEquals(PLAINTEXT, decrypt(encryptUnsigned(seip(), PLAINTEXT)));
    }

    @Test
    void tamperedUnsignedMessageRejected() throws Exception {
        var message = encryptUnsigned(seip(), PLAINTEXT);
        // one bit inside the encrypted literal data: CFB decrypts it to 17 corrupted bytes
        message[message.length - 200] ^= 0x01;

        var exception = assertThrows(PGPException.class, () -> decrypt(message));
        assertThat(exception.getMessage(), containsString("Integrity check failed"));
    }

    @Test
    void tamperedMessageFromEncryptTaskNeverYieldsCorruptedOutput() throws Exception {
        // weakly compressible content: ZIP (raw DEFLATE, no checksum) then rarely breaks on a
        // flipped bit, so without the integrity check most flips decrypt to corrupted output
        var plaintext = weaklyCompressibleText(123);

        var encrypt = Encrypt.builder()
            .from(Property.ofValue(storeFile(plaintext).toString()))
            .key(Property.ofValue(readResource("pgp/contact-key.pub")))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        var encryptOutput = encrypt.run(runContextFactory.of());

        var armored = IOUtils.toByteArray(storageInterface.get(TenantService.MAIN_TENANT, null, encryptOutput.getUri()));
        var message = IOUtils.toByteArray(PGPUtil.getDecoderStream(new ByteArrayInputStream(armored)));
        assertArrayEquals(plaintext, decrypt(message));

        assertThat(countCorruptedOutputs(message, plaintext), is(0));
    }

    @Test
    void tamperedSignedMessageWithoutSignUsersKeyNeverYieldsCorruptedOutput() throws Exception {
        // without signUsersKey the one-pass signature is not verified, so the MDC is the only
        // integrity check left on this path
        var plaintext = weaklyCompressibleText(456);
        var encrypt = Encrypt.builder()
            .from(Property.ofValue(storeFile(plaintext).toString()))
            .key(Property.ofValue(readResource("pgp/contact-key.pub")))
            .signPublicKey(Property.ofValue(readResource("pgp/hello-key.pub")))
            .signPrivateKey(Property.ofValue(readResource("pgp/hello-key.sec")))
            .signPassphrase(Property.ofValue("abc456"))
            .signUser(Property.ofValue("hello@kestra.io"))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        var encryptOutput = encrypt.run(runContextFactory.of());

        var armored = IOUtils.toByteArray(storageInterface.get(TenantService.MAIN_TENANT, null, encryptOutput.getUri()));
        var message = IOUtils.toByteArray(PGPUtil.getDecoderStream(new ByteArrayInputStream(armored)));
        assertArrayEquals(plaintext, decrypt(message));

        assertThat(countCorruptedOutputs(message, plaintext), is(0));
    }

    private static byte[] weaklyCompressibleText(long seed) {
        var random = new Random(seed);
        var content = new StringBuilder();
        for (int i = 0; i < 400; i++) {
            content.append(Long.toString(random.nextLong(), 36)).append(' ');
        }

        return content.toString().getBytes(StandardCharsets.UTF_8);
    }

    private int countCorruptedOutputs(byte[] message, byte[] plaintext) {
        var corruptedOutputs = 0;
        for (int position = 60; position < message.length - 30; position += 97) {
            var tampered = message.clone();
            tampered[position] ^= 0x01;
            try {
                if (!Arrays.equals(plaintext, decrypt(tampered))) {
                    corruptedOutputs++;
                }
            } catch (Exception e) {
                // expected: the tampered message is rejected, either by the integrity check or earlier
                // when the flip breaks a packet header, the session key or the compressed stream
            }
        }

        return corruptedOutputs;
    }

    @Test
    void aeadV5MessageStillDecrypts() throws Exception {
        // BouncyCastle reports isIntegrityProtected() == false for AEAD v5 (OCB, as written by
        // GnuPG 2.3+), so it must not be mistaken for a legacy SED packet
        var encryptor = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
            .setWithAEAD(AEADAlgorithmTags.OCB, 6)
            .setUseV5AEAD();

        assertArrayEquals(PLAINTEXT, decrypt(encryptUnsigned(encryptor, PLAINTEXT)));
    }

    @Test
    void aeadV6MessageStillDecrypts() throws Exception {
        var encryptor = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
            .setWithAEAD(AEADAlgorithmTags.OCB, 6)
            .setUseV6AEAD();

        assertArrayEquals(PLAINTEXT, decrypt(encryptUnsigned(encryptor, PLAINTEXT)));
    }

    @Test
    void tamperedAeadFinalTagOnSignedMessageWithoutSignUsersKeyRejected() throws Exception {
        // without signUsersKey nothing reads past the literal data, so the trailing signature and
        // the final AEAD tag are only checked when the stream is drained
        var message = encryptSigned(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 6).setUseV5AEAD(),
            PLAINTEXT
        );
        assertArrayEquals(PLAINTEXT, decrypt(message));

        var tampered = message.clone();
        tampered[tampered.length - 1] ^= 0x01;

        var exception = assertThrows(PGPException.class, () -> decrypt(tampered));
        assertThat(exception.getMessage(), containsString("Integrity check failed"));
    }

    @Test
    void tamperedAeadChunkRejected() throws Exception {
        var message = encryptUnsigned(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 6).setUseV6AEAD(),
            PLAINTEXT
        );
        message[message.length / 2] ^= 0x01;

        var exception = assertThrows(PGPException.class, () -> decrypt(message));
        assertThat(exception.getMessage(), containsString("Integrity check failed"));
    }

    @Test
    void tamperedAeadV5MessageRejectedWithIntegrityError() throws Exception {
        // a single chunk covers the whole message, so BC authenticates it while opening the stream
        var message = encryptUnsigned(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithAEAD(AEADAlgorithmTags.OCB, 22).setUseV5AEAD(),
            PLAINTEXT
        );
        message[message.length / 2] ^= 0x01;

        var exception = assertThrows(PGPException.class, () -> decrypt(message));
        assertThat(exception.getMessage(), containsString("Integrity check failed"));
    }

    @Test
    void truncatedMessageRejected() throws Exception {
        var message = encryptUnsigned(seip(), PLAINTEXT);
        var truncated = Arrays.copyOf(message, message.length - 100);

        var exception = assertThrows(PGPException.class, () -> decrypt(truncated));
        assertThat(exception.getMessage(), containsString("could not be read or authenticated"));
    }

    @Test
    void corruptedSessionKeyIsNotReportedAsTampering() throws Exception {
        var message = encryptUnsigned(seip(), PLAINTEXT);
        // inside the RSA-encrypted session key of the first packet: a key problem, not a modified payload
        message[100] ^= 0x01;

        var exception = assertThrows(PGPException.class, () -> decrypt(message));
        assertThat(exception.getMessage(), containsString("exception decrypting session data"));
    }

    @Test
    void legacySedMessageRejected() throws Exception {
        var encryptor = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(false);

        var exception = assertThrows(PGPException.class, () -> decrypt(encryptUnsigned(encryptor, PLAINTEXT)));
        assertThat(exception.getMessage(), containsString("not integrity protected"));
    }
}
