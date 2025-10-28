package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotNull;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.slf4j.Logger;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(title = "Encrypt a file with PGP (fully compatible with old plugin).")
@Plugin(
    examples = {
        @Example(
            title = "Encrypt a file not signed",
            full = true,
            code = """
                id: crypto_encrypt
                namespace: company.team

                inputs:
                  - id: file
                    type: FILE

                tasks:
                  - id: encrypt
                    type: io.kestra.plugin.crypto.openpgp.Encrypt
                    from: "{{ inputs.file }}"
                    key: |
                      -----BEGIN PGP PUBLIC KEY BLOCK----- ...
                    recipients:
                      - hello@kestra.io
                """
        ),
        @Example(
            title = "Encrypt a file signed",
            full = true,
            code = """
                id: crypto_encrypt
                namespace: company.team

                inputs:
                  - id: file
                    type: FILE

                tasks:
                  - id: encrypt
                    type: io.kestra.plugin.crypto.openpgp.Encrypt
                    from: "{{ inputs.file }}"
                    key: |
                      -----BEGIN PGP PUBLIC KEY BLOCK----- ...
                    recipients:
                      - hello@kestra.io
                    signPublicKey: |
                      -----BEGIN PGP PUBLIC KEY BLOCK----- ...
                    signPrivateKey: |
                      -----BEGIN PGP PRIVATE KEY BLOCK-----
                    signPassphrase: my-passphrase
                    signUser: signer@kestra.io
                """
        )
    }
)
public class Encrypt extends AbstractPgp implements RunnableTask<Encrypt.Output> {
    @Schema(
        title = "The file to crypt"
    )
    @PluginProperty(internalStorageURI = true)
    private Property<String> from;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    private Property<String> key;

    @Schema(
        title = "The list of recipients the file will be generated."
    )
    @NotNull
    private Property<List<String>> recipients;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    private Property<String> signPublicKey;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    private Property<String> signPrivateKey;

    @Schema(
        title = "The passphrase use to unlock the secret ring"
    )
    protected Property<String> signPassphrase;

    @Schema(
        title = "The user that will signed the files",
        description = "If you want to sign the file, you need to provide a `privateKey`"
    )
    private Property<String> signUser;

    @Override
    public Encrypt.Output run(RunContext runContext) throws Exception {
        var logger = runContext.logger();

        AbstractPgp.addProvider();

        var rFrom = URI.create(runContext.render(this.from).as(String.class).orElseThrow());
        File outFile = runContext.workingDir().createTempFile().toFile();

        var rKey = runContext.render(this.key).as(String.class).orElseThrow();

        PGPPublicKeyRingCollection pubKeyRings;
        try (var pubKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(rKey.getBytes(StandardCharsets.UTF_8)))) {
            pubKeyRings = new PGPPublicKeyRingCollection(pubKeyIn, new JcaKeyFingerprintCalculator());
        }

        PGPPublicKey encryptionKey = pubKeyRings.getKeyRings().next().getPublicKey();

        PGPSignatureGenerator signatureGenerator = null;
        if (this.signPrivateKey != null && this.signUser != null) {
            var rSignPrivateKey = runContext.render(this.signPrivateKey).as(String.class).orElseThrow();
            var rSignPassphrase = runContext.render(this.signPassphrase).as(String.class).orElse("").toCharArray();

            InputStream privKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(rSignPrivateKey.getBytes(StandardCharsets.UTF_8)));
            var secretKeyRings = new PGPSecretKeyRingCollection(privKeyIn, new JcaKeyFingerprintCalculator());
            PGPSecretKey signingSecretKey = secretKeyRings.getKeyRings().next().getSecretKey();
            PGPPrivateKey signingPrivateKey = signingSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(rSignPassphrase));

            PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
                signingSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA256
            );

            signatureGenerator = new PGPSignatureGenerator(signerBuilder, signingSecretKey.getPublicKey());
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingPrivateKey);

        }

        try (OutputStream fileOut = new BufferedOutputStream(new FileOutputStream(outFile));
             var armoredOut = new ArmoredOutputStream(fileOut);
             InputStream input = runContext.storage().getFile(rFrom)) {

            var encryptor = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256)
                .setWithIntegrityPacket(true)
                .setSecureRandom(new SecureRandom());

            var encGen = new PGPEncryptedDataGenerator(encryptor);
            encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encryptionKey));

            try (OutputStream encOut = encGen.open(armoredOut, new byte[4096])) {
                var comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);
                try (var compressedOut = comData.open(encOut)) {
                    if (signatureGenerator != null) {
                        signatureGenerator.generateOnePassVersion(false).encode(compressedOut);
                    }

                    PGPLiteralDataGenerator literalGen = new PGPLiteralDataGenerator();
                    try (var literalOut = literalGen.open(
                        compressedOut, PGPLiteralData.BINARY, "data", new Date(), new byte[4096])) {

                        int ch;
                        while ((ch = input.read()) >= 0) {
                            if (signatureGenerator != null) {
                                signatureGenerator.update((byte) ch);
                            }
                            literalOut.write(ch);
                        }
                    }

                    if (signatureGenerator != null) {
                        signatureGenerator.generate().encode(compressedOut);
                    }
                }
            }
        }

        URI uri = runContext.storage().putFile(outFile);
        logger.debug("Encrypted file at '{}", uri);

        return Output.builder()
            .uri(uri)
            .build();
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(
            title = "The encrypted files uri"
        )
        private final URI uri;
    }
}
