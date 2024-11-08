package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import lombok.experimental.SuperBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildDecryptionInputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;

import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.util.List;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Decrypt a file encrypted with PGP"
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
        URI from = URI.create(runContext.render(this.from).as(String.class).orElseThrow());
        File outFile = runContext.workingDir().createTempFile().toFile();

        final InMemoryKeyring keyringConfig = KeyringConfigs.forGpgExportedKeys(keyringConfig(runContext, this.privateKeyPassphrase));

        if (this.privateKey != null) {
            keyringConfig.addSecretKey(runContext.render(this.privateKey).as(String.class).orElseThrow().getBytes());
        }

        for (String s : runContext.render(this.signUsersKey).asList(String.class)) {
            keyringConfig.addPublicKey(runContext.render(s).getBytes());
        }

        AbstractPgp.addProvider();

        try (
            final FileOutputStream fileOutput = new FileOutputStream(outFile);
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput);
            final InputStream inputStream = runContext.storage().getFile(from);
        ) {
            BuildDecryptionInputStreamAPI.ValidationWithKeySelectionStrategy builder = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(keyringConfig);

            BuildDecryptionInputStreamAPI.Build build;
            if (requiredSignerUsers != null) {
                build = builder.andRequireSignatureFromAllKeys(
                    runContext.render(this.requiredSignerUsers).asList(String.class).toArray(String[]::new)
                );
            } else {
                build = builder.andIgnoreSignatures();
            }

            try (InputStream decrypt = build.fromEncryptedInputStream(inputStream)) {
                Streams.pipeAll(decrypt, bufferedOut);
            }
        }

        URI uri = runContext.storage().putFile(outFile);
        logger.debug("Decrypted file at '{}", uri);

        return Decrypt.Output.builder()
            .uri(uri)
            .build();
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
