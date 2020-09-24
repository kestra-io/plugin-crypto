package org.kestra.task.crypto.openpgp;

import lombok.*;
import lombok.experimental.SuperBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.util.io.Streams;
import org.kestra.core.exceptions.IllegalVariableEvaluationException;
import org.kestra.core.models.annotations.Documentation;
import org.kestra.core.models.annotations.Example;
import org.kestra.core.models.annotations.InputProperty;
import org.kestra.core.models.annotations.OutputProperty;
import org.kestra.core.models.tasks.RunnableTask;
import org.kestra.core.models.tasks.Task;
import org.kestra.core.runners.RunContext;
import org.slf4j.Logger;

import java.io.*;
import java.net.URI;
import java.util.List;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Documentation(
    description = "Encrypt a file crypted with PGP"
)
@Example(
    title = "Encrypt a file not signed",
    code = {
        "from: \"{{ inputs.file }}\"",
        "key: |",
        "  -----BEGIN PGP PUBLIC KEY BLOCK----- ... ",
        "recipients:",
        "  - hello@kestra.io",
    }
)
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
public class Encrypt extends Task implements RunnableTask<Encrypt.Output> {
    @InputProperty(
        description = "The file to crypt",
        dynamic = true
    )
    private String from;

    @InputProperty(
        description = "The public key use to sign the files",
        body = "Must be an ascii key export with `gpg --export -a`",
        dynamic = true
    )
    private String key;

    @InputProperty(
        description = "The list of recipients the file will be generated.",
        dynamic = true
    )
    private List<String> recipients;

    @InputProperty(
        description = "The public key use to sign the files",
        body = "Must be an ascii key export with `gpg --export -a`",
        dynamic = true
    )
    private String signPublicKey;

    @InputProperty(
        description = "The public key use to sign the files",
        body = "Must be an ascii key export with `gpg --export -a`",
        dynamic = true
    )
    private String signPrivateKey;

    @InputProperty(
        description = "The passphrase use to unlock the secret ring",
        dynamic = true
    )
    protected String signPassphrase;

    @InputProperty(
        description = "The user that will signed the files",
        body = "If you want to sign the file, you need to provide a `privateKey`",
        dynamic = true
    )
    private String signUser;

    @Override
    public Encrypt.Output run(RunContext runContext) throws Exception {
        Logger logger = runContext.logger();
        URI from = URI.create(runContext.render(this.from));
        File outFile = File.createTempFile(this.getClass().getSimpleName().toLowerCase() + "_", ".pgp");

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

        BouncyGPG.registerProvider();

        try (
            final FileOutputStream fileOutput = new FileOutputStream(outFile);
            final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput);
            final InputStream inputStream = runContext.uriToInputStream(from);
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

        URI uri = runContext.putTempFile(outFile);
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
    public static class Output implements org.kestra.core.models.tasks.Output {
        @OutputProperty(
            body = "The encrypted files uri"
        )
        private final URI uri;
    }
}
