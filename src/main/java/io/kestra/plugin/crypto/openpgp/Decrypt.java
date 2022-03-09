package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
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
    title = "Decrypt a file crypted with PGP"
)
@Plugin(
    examples = {
        @Example(
            title = "Decrypt a file",
            code = {
                "from: \"{{ inputs.file }}\"",
                "privateKey: |",
                "  -----BEGIN PGP PRIVATE KEY BLOCK-----",
                "privateKeyPassphrase: my-passphrase",
            }
        ),
        @Example(
            title = "Decrypt a file and verify signature",
            code = {
                "from: \"{{ inputs.file }}\"",
                "privateKey: |",
                "  -----BEGIN PGP PRIVATE KEY BLOCK-----",
                "privateKeyPassphrase: my-passphrase",
                "signUsersKey: ",
                "  - |",
                "    -----BEGIN PGP PRIVATE KEY BLOCK-----",
                "requiredSignerUsers: ",
                "  - signer@kestra.io",
            }
        )
    }
)
public class Decrypt extends AbstractPgp implements RunnableTask<Decrypt.Output> {
    @Schema(
        title = "The file to crypt"
    )
    @PluginProperty(dynamic = true)
    private String from;

    @Schema(
        title = "The private key to decrypt",
        description = "Must be an ascii key export with `gpg --export-secret-key -a`"
    )
    @PluginProperty(dynamic = true)
    private String privateKey;

    @Schema(
        title = "The passphrase use to unlock the secret ring"
    )
    @PluginProperty(dynamic = true)
    protected String privateKeyPassphrase;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    @PluginProperty(dynamic = true)
    private List<String> signUsersKey;

    @Schema(
        title = "The list of recipients the file will be generated."
    )
    @PluginProperty(dynamic = true)
    private List<String> requiredSignerUsers;

    @Override
    public Decrypt.Output run(RunContext runContext) throws Exception {
        Logger logger = runContext.logger();
        URI from = URI.create(runContext.render(this.from));
        File outFile = runContext.tempFile().toFile();

        final InMemoryKeyring keyringConfig = KeyringConfigs.forGpgExportedKeys(keyringConfig(runContext, this.privateKeyPassphrase));

        if (this.privateKey != null) {
            keyringConfig.addSecretKey(runContext.render(this.privateKey).getBytes());
        }

        if (this.signUsersKey != null) {
            for (String s : this.signUsersKey) {
                keyringConfig.addPublicKey(runContext.render(s).getBytes());
            }
        }

        AbstractPgp.addProvider();

        try (
            final FileOutputStream fileOutput = new FileOutputStream(outFile);
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput);
            final InputStream inputStream = runContext.uriToInputStream(from);
        ) {
            BuildDecryptionInputStreamAPI.ValidationWithKeySelectionStrategy builder = BouncyGPG
                .decryptAndVerifyStream()
                .withConfig(keyringConfig);

            BuildDecryptionInputStreamAPI.Build build;
            if (requiredSignerUsers != null) {
                build = builder.andRequireSignatureFromAllKeys(
                    runContext.render(this.requiredSignerUsers).toArray(String[]::new)
                );
            } else {
                build = builder.andIgnoreSignatures();
            }

            try (InputStream decrypt = build.fromEncryptedInputStream(inputStream)) {
                Streams.pipeAll(decrypt, bufferedOut);
            }
        }

        URI uri = runContext.putTempFile(outFile);
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
