package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import lombok.experimental.SuperBuilder;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static io.kestra.core.utils.Rethrow.throwFunction;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Decrypt a file encrypted with PGP."
)
@Plugin(
    examples = {
        @Example(
            title = "Decrypt a file",
            full = true,
            code = """
                id: crypto_decrypt
                namespace: company.team

                inputs:
                  - id: file
                    type: FILE

                tasks:
                  - id: decrypt
                    type: io.kestra.plugin.crypto.openpgp.Decrypt
                    from: "{{ inputs.file }}"
                    privateKey: |
                      -----BEGIN PGP PRIVATE KEY BLOCK-----
                    privateKeyPassphrase: my-passphrase
                """
        ),
        @Example(
            title = "Decrypt a file and verify signature",
            full = true,
            code = """
                id: crypto_decrypt
                namespace: company.team

                inputs:
                  - id: file
                    type: FILE

                tasks:
                  - id: decrypt
                    type: io.kestra.plugin.crypto.openpgp.Decrypt
                    from: "{{ inputs.file }}"
                    privateKey: |
                      -----BEGIN PGP PRIVATE KEY BLOCK-----
                    privateKeyPassphrase: my-passphrase
                    signUsersKey:
                      - |
                        -----BEGIN PGP PRIVATE KEY BLOCK-----
                    requiredSignerUsers:
                      - signer@kestra.io
                """
        )
    }
)
public class Decrypt extends AbstractPgp implements RunnableTask<Decrypt.Output> {
    @Schema(
        title = "The file to crypt"
    )
    @PluginProperty(internalStorageURI = true)
    private Property<String> from;

    @Schema(
        title = "The private key to decrypt",
        description = "Must be an ascii key export with `gpg --export-secret-key -a`"
    )
    private Property<String> privateKey;

    @Schema(
        title = "The passphrase use to unlock the secret ring"
    )
    protected Property<String> privateKeyPassphrase;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    private Property<List<String>> signUsersKey;

    @Schema(
        title = "The list of recipients the file will be generated."
    )
    private Property<List<String>> requiredSignerUsers;

    @Override
    public Decrypt.Output run(RunContext runContext) throws Exception {
        Logger logger = runContext.logger();

        var rFrom = URI.create(runContext.render(this.from).as(String.class).orElseThrow());
        var rSignKeys = runContext.render(this.signUsersKey).asList(String.class);
        File outFile = runContext.workingDir().createTempFile().toFile();

        AbstractPgp.addProvider();

        var rPrivateKey = runContext.render(this.privateKey).as(String.class).orElseThrow();
        var rPassphrase = runContext.render(this.privateKeyPassphrase).as(String.class).orElse("").toCharArray();

        var secretKeys = new PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(new ByteArrayInputStream(rPrivateKey.getBytes(StandardCharsets.UTF_8))),
            new JcaKeyFingerprintCalculator()
        );

        List<PGPPublicKeyRingCollection> signerKeyrings = new ArrayList<>();

        if (rSignKeys != null && !rSignKeys.isEmpty()) {
            signerKeyrings = rSignKeys.stream()
                .map(throwFunction(key -> {
                    try (InputStream pubKeyIn = PGPUtil.getDecoderStream(
                        new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8)))) {
                        return new PGPPublicKeyRingCollection(pubKeyIn, new JcaKeyFingerprintCalculator());
                    }
                }))
                .filter(Objects::nonNull)
                .toList();
        }


        try (InputStream encryptedIn = PGPUtil.getDecoderStream(runContext.storage().getFile(rFrom));
             var fileOut = new BufferedOutputStream(new FileOutputStream(outFile))) {

            var pgpFactory = new PGPObjectFactory(encryptedIn, new JcaKeyFingerprintCalculator());
            Object object = pgpFactory.nextObject();
            if (!(object instanceof PGPEncryptedDataList))
                object = pgpFactory.nextObject();

            PGPEncryptedDataList encList = (PGPEncryptedDataList) object;
            PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData) encList.getEncryptedDataObjects().next();

            PGPSecretKey secretKey = secretKeys.getSecretKey(encData.getKeyIdentifier().getKeyId());
            if (secretKey == null) {
                throw new PGPException("No private key found for this message");
            }

            PGPPrivateKey privateKey = secretKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder().build(rPassphrase)
            );


            try (InputStream clear = encData.getDataStream(
                new JcePublicKeyDataDecryptorFactoryBuilder().build(privateKey))) {

                PGPObjectFactory plainFactory = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
                Object message = plainFactory.nextObject();

                if (message == null) {
                    throw new PGPException("No PGP message found after decryption");
                }

                if (message instanceof PGPCompressedData compressed) {
                    plainFactory = new PGPObjectFactory(compressed.getDataStream(), new JcaKeyFingerprintCalculator());
                    message = plainFactory.nextObject();
                }

                if (message instanceof PGPLiteralData literal) {
                    Streams.pipeAll(literal.getInputStream(), fileOut);
                }

                else if (message instanceof PGPOnePassSignatureList sigList) {
                    PGPOnePassSignature sig = sigList.get(0);
                    PGPPublicKey signerKey = findPublicKey(signerKeyrings, sig.getKeyID());
                    if (signerKey != null) {
                        sig.init(new JcaPGPContentVerifierBuilderProvider(), signerKey);
                    }

                    PGPLiteralData literal = (PGPLiteralData) plainFactory.nextObject();
                    try (InputStream dIn = literal.getInputStream()) {
                        Streams.pipeAll(new FilterInputStream(dIn) {
                            @Override
                            public int read() throws IOException {
                                int ch = super.read();
                                if (ch >= 0 && signerKey != null) {
                                    sig.update((byte) ch);
                                }
                                return ch;
                            }
                        }, fileOut);
                    }
                } else {
                    throw new PGPException("Unknown PGP message type: " + message.getClass());
                }
            }
        }

        URI uri = runContext.storage().putFile(outFile);
        logger.debug("Decrypted file at '{}", uri);

        return Decrypt.Output.builder()
            .uri(uri)
            .build();
    }

    private PGPPublicKey findPublicKey(List<PGPPublicKeyRingCollection> collections, long keyID) throws PGPException {
        for (PGPPublicKeyRingCollection c : collections) {
            PGPPublicKey publicKey = c.getPublicKey(keyID);
            if (publicKey != null) {
                return publicKey;
            }
        }
        return null;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(
            title = "The decrypted files uri"
        )
        private final URI uri;
    }
}
