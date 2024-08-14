package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import lombok.experimental.SuperBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;

import jakarta.validation.constraints.NotNull;
import java.io.*;
import java.net.URI;
import java.util.List;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Encrypt a file with PGP"
)
@Plugin(
    examples = {
        @Example(
            title = "Encrypt a file not signed",
            code = {
                "from: \"{{ inputs.file }}\"",
                "key: |",
                "  -----BEGIN PGP PUBLIC KEY BLOCK----- ... ",
                "recipients:",
                "  - hello@kestra.io",
            }
        ),
        @Example(
            title = "Encrypt a file signed",
            code = {
                "from: \"{{ inputs.file }}\"",
                "key: |",
                "  -----BEGIN PGP PUBLIC KEY BLOCK----- ... ",
                "recipients:",
                "  - hello@kestra.io",
                "signPublicKey: |",
                "  -----BEGIN PGP PUBLIC KEY BLOCK----- ... ",
                "signPrivateKey: |",
                "  -----BEGIN PGP PRIVATE KEY BLOCK-----",
                "signPassphrase: my-passphrase",
                "signUser: signer@kestra.io"
            }
        )
    }
)
public class Encrypt extends AbstractPgp implements RunnableTask<Encrypt.Output> {
    @Schema(
        title = "The file to crypt"
    )
    @PluginProperty(dynamic = true)
    private String from;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    @PluginProperty(dynamic = true)
    private String key;

    @Schema(
        title = "The list of recipients the file will be generated."
    )
    @NotNull
    @PluginProperty(dynamic = true)
    private List<String> recipients;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    @PluginProperty(dynamic = true)
    private String signPublicKey;

    @Schema(
        title = "The public key use to sign the files",
        description = "Must be an ascii key export with `gpg --export -a`"
    )
    @PluginProperty(dynamic = true)
    private String signPrivateKey;

    @Schema(
        title = "The passphrase use to unlock the secret ring"
    )
    @PluginProperty(dynamic = true)
    protected String signPassphrase;

    @Schema(
        title = "The user that will signed the files",
        description = "If you want to sign the file, you need to provide a `privateKey`"
    )
    @PluginProperty(dynamic = true)
    private String signUser;

    @Override
    public Encrypt.Output run(RunContext runContext) throws Exception {
        Logger logger = runContext.logger();
        List<String> recipients = runContext.render(this.recipients);
        URI from = URI.create(runContext.render(this.from));
        File outFile = runContext.workingDir().createTempFile().toFile();

        final InMemoryKeyring keyringConfig = KeyringConfigs.forGpgExportedKeys(keyringConfig(runContext));

        if (this.key != null) {
            keyringConfig.addPublicKey(runContext.render(this.key).getBytes());
        }

        if (this.signPublicKey != null) {
            keyringConfig.addPublicKey(runContext.render(this.signPublicKey).getBytes());
        }

        if (this.signPrivateKey != null) {
            keyringConfig.addSecretKey(runContext.render(this.signPrivateKey).getBytes());
        }

        AbstractPgp.addProvider();

        try (
            final FileOutputStream fileOutput = new FileOutputStream(outFile);
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput);
            final InputStream inputStream = runContext.storage().getFile(from);
        ) {
            BuildEncryptionOutputStreamAPI.WithAlgorithmSuite.To.SignWith builder = BouncyGPG
                .encryptToStream()
                .withConfig(keyringConfig)
                .withStrongAlgorithms()
                .toRecipients(recipients.toArray(String[]::new));

            BuildEncryptionOutputStreamAPI.WithAlgorithmSuite.To.SignWith.Armor armor;

            if (signUser != null) {
                armor = builder.andSignWith(this.signUser);
            } else {
                armor = builder.andDoNotSign();
            }

            try (OutputStream outputStream = armor.binaryOutput().andWriteTo(bufferedOut)) {
                Streams.pipeAll(inputStream, outputStream);
            }
        }

        URI uri = runContext.storage().putFile(outFile);
        logger.debug("Encrypted file at '{}", uri);

        return Output.builder()
            .uri(uri)
            .build();
    }

    protected KeyringConfigCallback keyringConfig(RunContext runContext) throws IllegalVariableEvaluationException {
        if (this.signPassphrase != null) {
            return KeyringConfigCallbacks.withPassword(runContext.render(this.signPassphrase));
        } else {
            return KeyringConfigCallbacks.withUnprotectedKeys();
        }
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
