package io.kestra.plugin.crypto.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Objects;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
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
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * {@link Decrypt} only looked at the first recipient of a message, so a message encrypted to
 * several recipients could not be decrypted by any recipient but the first one.
 */
@KestraTest
class DecryptMultipleRecipientsTest {
    private static final byte[] PLAINTEXT = "Kestra crypto plugin multiple recipients test payload".getBytes(StandardCharsets.UTF_8);

    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private StorageInterface storageInterface;

    private static String readResource(String name) throws Exception {
        return IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        DecryptMultipleRecipientsTest.class.getClassLoader().getResource(name)
                    ).toURI()
                )
            ),
            StandardCharsets.US_ASCII
        );
    }

    private static PGPPublicKey encryptionKey(String publicKeyResource) throws Exception {
        try (var pubKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(readResource(publicKeyResource).getBytes(StandardCharsets.UTF_8)))) {
            var ring = new PGPPublicKeyRingCollection(pubKeyIn, new JcaKeyFingerprintCalculator()).getKeyRings().next();
            PGPPublicKey encryptionKey = null;
            for (var keys = ring.getPublicKeys(); keys.hasNext();) {
                var key = keys.next();
                if (key.isEncryptionKey()) {
                    encryptionKey = key;
                }
            }
            return encryptionKey;
        }
    }

    private static PGPEncryptedDataGenerator encryptedDataGenerator() {
        AbstractPgp.addProvider();

        return new PGPEncryptedDataGenerator(
            new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom())
        );
    }

    /** Encrypts to each public key, in order: one PKESK packet per recipient. */
    private static byte[] encryptTo(String... publicKeyResources) throws Exception {
        var encGen = encryptedDataGenerator();
        for (var publicKeyResource : publicKeyResources) {
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey(publicKeyResource)));
        }

        return writeLiteral(encGen);
    }

    private static byte[] writeLiteral(PGPEncryptedDataGenerator encGen) throws Exception {
        var byteOut = new ByteArrayOutputStream();
        try (
            OutputStream encOut = encGen.open(byteOut, new byte[4096]);
            var literalOut = new PGPLiteralDataGenerator().open(encOut, PGPLiteralData.BINARY, "data", new Date(), new byte[4096])
        ) {
            literalOut.write(PLAINTEXT);
        }

        return byteOut.toByteArray();
    }

    private byte[] decrypt(byte[] message, String privateKeyResource) throws Exception {
        var fileStorage = storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new ByteArrayInputStream(message)
        );

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .privateKey(Property.ofValue(readResource(privateKeyResource)))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .build();
        var output = decrypt.run(runContextFactory.of());

        return IOUtils.toByteArray(storageInterface.get(TenantService.MAIN_TENANT, null, output.getUri()));
    }

    @Test
    void firstRecipientDecrypts() throws Exception {
        assertArrayEquals(PLAINTEXT, decrypt(encryptTo("pgp/contact-key.pub", "pgp/hello-key.pub"), "pgp/contact-key.sec"));
    }

    @Test
    void secondRecipientDecrypts() throws Exception {
        // e.g. a sender that encrypts to themselves first: gpg -r sender -r recipient
        assertArrayEquals(PLAINTEXT, decrypt(encryptTo("pgp/hello-key.pub", "pgp/contact-key.pub"), "pgp/contact-key.sec"));
    }

    @Test
    void everyRecipientDecryptsTheSameMessage() throws Exception {
        var message = encryptTo("pgp/hello-key.pub", "pgp/contact-key.pub");

        assertArrayEquals(PLAINTEXT, decrypt(message, "pgp/hello-key.sec"));
        assertArrayEquals(PLAINTEXT, decrypt(message, "pgp/contact-key.sec"));
    }

    @Test
    void nonRecipientRejected() throws Exception {
        var message = encryptTo("pgp/contact-key.pub");

        var exception = assertThrows(PGPException.class, () -> decrypt(message, "pgp/hello-key.sec"));
        assertThat(exception.getMessage(), containsString("No private key found"));
    }

    @Test
    void recipientAfterPasswordPacketDecrypts() throws Exception {
        // e.g. gpg --symmetric --encrypt -r recipient
        var encGen = encryptedDataGenerator();
        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator("a password".toCharArray()));
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey("pgp/contact-key.pub")));
        var message = writeLiteral(encGen);

        assertArrayEquals(PLAINTEXT, decrypt(message, "pgp/contact-key.sec"));
    }

    @Test
    void passwordOnlyMessageRejectedWithClearError() throws Exception {
        var encGen = encryptedDataGenerator();
        encGen.addMethod(new JcePBEKeyEncryptionMethodGenerator("a password".toCharArray()));
        var message = writeLiteral(encGen);

        var exception = assertThrows(PGPException.class, () -> decrypt(message, "pgp/contact-key.sec"));
        assertThat(exception.getMessage(), containsString("No private key found"));
    }
}
