package org.kestra.task.crypto.openpgp;

import lombok.*;
import lombok.experimental.SuperBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildDecryptionInputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.util.io.Streams;
import org.kestra.core.models.annotations.Documentation;
import org.kestra.core.models.annotations.Example;
import org.kestra.core.models.annotations.InputProperty;
import org.kestra.core.models.annotations.OutputProperty;
import org.kestra.core.models.tasks.RunnableTask;
import org.kestra.core.runners.RunContext;
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
@Documentation(
    description = "Decrypt a file crypted with PGP"
)
@Example(
    title = "Decrypt a file",
    code = {
        "from: \"{{ inputs.file }}\"",
        "privateKey: |",
        "  -----BEGIN PGP PRIVATE KEY BLOCK-----",
        "privateKeyPassphrase: my-passphrase",
    }
)
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
public class Decrypt extends AbstractPgp implements RunnableTask<Decrypt.Output> {
    @InputProperty(
        description = "The file to crypt",
        dynamic = true
    )
    private String from;

    @InputProperty(
        description = "The private key to decrypt",
        body = "Must be an ascii key export with `gpg --export-secret-key -a`",
        dynamic = true
    )
    private String privateKey;

    @InputProperty(
        description = "The passphrase use to unlock the secret ring",
        dynamic = true
    )
    protected String privateKeyPassphrase;

    @InputProperty(
        description = "The public key use to sign the files",
        body = "Must be an ascii key export with `gpg --export -a`",
        dynamic = true
    )
    private List<String> signUsersKey;

    @InputProperty(
        description = "The list of recipients the file will be generated.",
        dynamic = true
    )
    private List<String> requiredSignerUsers;

    @Override
    public Decrypt.Output run(RunContext runContext) throws Exception {
        Logger logger = runContext.logger();
        URI from = URI.create(runContext.render(this.from));
        File outFile = File.createTempFile(this.getClass().getSimpleName().toLowerCase() + "_", ".pgp");

        final InMemoryKeyring keyringConfig = KeyringConfigs.forGpgExportedKeys(keyringConfig(runContext, this.privateKeyPassphrase));

        if (this.privateKey != null) {
            keyringConfig.addSecretKey(runContext.render(this.privateKey).getBytes());
        }

        if (this.signUsersKey != null) {
            for (String s : this.signUsersKey) {
                keyringConfig.addPublicKey(runContext.render(s).getBytes());
            }
        }

        BouncyGPG.registerProvider();

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
    public static class Output implements org.kestra.core.models.tasks.Output {
        @OutputProperty(
            body = "The decrypted files uri"
        )
        private final URI uri;
    }
}
