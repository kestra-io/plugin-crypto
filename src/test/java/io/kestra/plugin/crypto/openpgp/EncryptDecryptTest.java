package io.kestra.plugin.crypto.openpgp;

import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Objects;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.junit.jupiter.api.Test;

import com.devskiller.friendly_id.FriendlyId;
import com.google.common.io.CharStreams;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.storages.StorageInterface;
import io.kestra.core.tenant.TenantService;

import jakarta.inject.Inject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@KestraTest
class EncryptDecryptTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private StorageInterface storageInterface;

    private static String readPgpKey(String name) throws Exception {
        return IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        EncryptDecryptTest.class.getClassLoader().getResource("pgp/" + name)
                    ).toURI()
                )
            ),
            StandardCharsets.US_ASCII
        );
    }

    private static PGPPublicKey encryptionKey(String publicKey) throws Exception {
        try (var input = PGPUtil.getDecoderStream(new ByteArrayInputStream(publicKey.getBytes(StandardCharsets.UTF_8)))) {
            var keyRings = new PGPPublicKeyRingCollection(input, new JcaKeyFingerprintCalculator());
            return keyRings.getKeyRings().next().getPublicKey();
        }
    }

    private static byte[] encryptForRecipients(List<String> publicKeys, byte[] content) throws Exception {
        AbstractPgp.addProvider();
        var encrypted = new ByteArrayOutputStream();
        try (var armored = new ArmoredOutputStream(encrypted)) {
            var encryptor = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom());
            var generator = new PGPEncryptedDataGenerator(encryptor);
            for (String publicKey : publicKeys) {
                generator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey(publicKey)));
            }
            try (OutputStream compressedOutput = generator.open(armored, new byte[4096])) {
                var compressed = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                try (OutputStream literalOutput = compressed.open(compressedOutput)) {
                    var literal = new PGPLiteralDataGenerator();
                    try (OutputStream output = literal.open(
                        literalOutput, PGPLiteralData.BINARY, "data", new Date(), new byte[4096]
                    )) {
                        output.write(content);
                    }
                }
            }
        }
        return encrypted.toByteArray();
    }

    @Test
    void decryptsWhenItsRecipientPacketIsNotFirst() throws Exception {
        RunContext runContext = runContextFactory.of();
        byte[] cleartext = "multiple recipient message".getBytes(StandardCharsets.UTF_8);
        URI encrypted = storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new ByteArrayInputStream(
                encryptForRecipients(List.of(readPgpKey("hello-key.pub"), readPgpKey("contact-key.pub")), cleartext)
            )
        );

        var decrypt = Decrypt.builder()
            .from(Property.ofValue(encrypted.toString()))
            .privateKey(Property.ofValue(readPgpKey("contact-key.sec")))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .build();

        var output = decrypt.run(runContext);

        assertThat(
            CharStreams.toString(new InputStreamReader(storageInterface.get(TenantService.MAIN_TENANT, null, output.getUri()))),
            is(new String(cleartext, StandardCharsets.UTF_8))
        );
    }

    @Test
    void run() throws Exception {
        RunContext runContext = runContextFactory.of();

        String contactPublic = IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        EncryptDecryptTest.class.getClassLoader()
                            .getResource("pgp/contact-key.pub")
                    )
                        .toURI()
                )
            ), StandardCharsets.US_ASCII
        );

        String contactPrivate = IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        EncryptDecryptTest.class.getClassLoader()
                            .getResource("pgp/contact-key.sec")
                    )
                        .toURI()
                )
            ), StandardCharsets.US_ASCII
        );

        String helloPrivate = IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        EncryptDecryptTest.class.getClassLoader()
                            .getResource("pgp/hello-key.sec")
                    )
                        .toURI()
                )
            ), StandardCharsets.US_ASCII
        );

        String helloPublic = IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(
                        EncryptDecryptTest.class.getClassLoader()
                            .getResource("pgp/hello-key.pub")
                    )
                        .toURI()
                )
            ), StandardCharsets.US_ASCII
        );

        File file = new File(
            Objects.requireNonNull(
                EncryptDecryptTest.class.getClassLoader()
                    .getResource("application.yml")
            )
                .toURI()
        );

        URI fileStorage = storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new FileInputStream(file)
        );

        Encrypt encrypt = Encrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .key(Property.ofValue(contactPublic))
            .signPublicKey(Property.ofValue(helloPublic))
            .signPrivateKey(Property.ofValue(helloPrivate))
            .signPassphrase(Property.ofValue("abc456"))
            .signUser(Property.ofValue("hello@kestra.io"))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        Encrypt.Output encryptOutput = encrypt.run(runContext);

        Decrypt decrypt = Decrypt.builder()
            .from(Property.ofValue(encryptOutput.getUri().toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(helloPublic)))
            .requiredSignerUsers(Property.ofValue(Collections.singletonList("hello@kestra.io")))
            .build();
        Decrypt.Output decryptOutput = decrypt.run(runContext);

        assertThat(
            CharStreams.toString(new InputStreamReader(storageInterface.get(TenantService.MAIN_TENANT, null, decryptOutput.getUri()))),
            is(CharStreams.toString(new InputStreamReader(new FileInputStream(file))))
        );
    }

    @Test
    void runUnsigned() throws Exception {
        RunContext runContext = runContextFactory.of();

        String contactPublic = IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader().getResource("pgp/contact-key.pub")).toURI()
                )
            ), StandardCharsets.US_ASCII
        );

        String contactPrivate = IOUtils.toString(
            new FileInputStream(
                new File(
                    Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader().getResource("pgp/contact-key.sec")).toURI()
                )
            ), StandardCharsets.US_ASCII
        );

        File file = new File(
            Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader().getResource("application.yml")).toURI()
        );

        URI fileStorage = storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new FileInputStream(file)
        );

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
            .build();

        var decryptOutput = decrypt.run(runContext);

        assertThat(
            CharStreams.toString(new InputStreamReader(storageInterface.get(TenantService.MAIN_TENANT, null, decryptOutput.getUri()))),
            is(CharStreams.toString(new InputStreamReader(new FileInputStream(file))))
        );
    }

}
