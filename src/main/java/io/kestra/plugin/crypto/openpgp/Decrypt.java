package io.kestra.plugin.crypto.openpgp;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Objects;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;
import org.slf4j.Logger;

import io.kestra.core.models.annotations.Example;
import io.kestra.core.models.annotations.Plugin;
import io.kestra.core.models.annotations.PluginProperty;
import io.kestra.core.models.property.Property;
import io.kestra.core.models.tasks.RunnableTask;
import io.kestra.core.runners.RunContext;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.*;
import lombok.experimental.SuperBuilder;

import static io.kestra.core.utils.Rethrow.throwFunction;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Decrypt and optionally verify OpenPGP files",
    description = "Streams an ASCII-armored PGP message from Kestra storage, decrypts it with the provided secret key and optional passphrase, and returns the cleartext URI. When signer public keys are supplied, verifies a one-pass signature and can enforce specific signer user IDs."
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
                    privateKey: "{{ secret('PGP_PRIVATE_KEY') }}"
                    privateKeyPassphrase: "{{ secret('PGP_PRIVATE_KEY_PASSPHRASE') }}"
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
                    privateKey: "{{ secret('PGP_PRIVATE_KEY') }}"
                    privateKeyPassphrase: "{{ secret('PGP_PRIVATE_KEY_PASSPHRASE') }}"
                    signUsersKey:
                      - |
                        -----BEGIN PGP PUBLIC KEY BLOCK-----
                    requiredSignerUsers:
                      - signer@kestra.io
                """
        )
    }
)
public class Decrypt extends AbstractPgp implements RunnableTask<Decrypt.Output> {
    @Schema(
        title = "Source file to decrypt",
        description = "Kestra internal storage URI or templated path to the encrypted message."
    )
    @PluginProperty(internalStorageURI = true, group = "source")
    private Property<String> from;

    @Schema(
        title = "Private key for decryption",
        description = "ASCII-armored secret key export such as `gpg --export-secret-key -a`; the first key ring found is used."
    )
    @ToString.Exclude
    @PluginProperty(secret = true, group = "connection")
    private Property<String> privateKey;

    @Schema(
        title = "Passphrase for private key",
        description = "Leave empty for unprotected keys; required for most secret keys."
    )
    @ToString.Exclude
    @PluginProperty(secret = true, group = "connection")
    protected Property<String> privateKeyPassphrase;

    @Schema(
        title = "Allowed signer public keys",
        description = "Optional list of ASCII-armored public keys used to verify the message's one-pass signature. When set, decryption fails if the message is unsigned, if the signature was not produced by one of these keys, or if the signature itself does not verify."
    )
    @PluginProperty(group = "connection")
    private Property<List<String>> signUsersKey;

    @Schema(
        title = "Required signer user IDs",
        description = "Optional list of allowed signer identities, e.g. `signer@kestra.io`. Requires `signUsersKey` to also be set, since the signer's identity is read from the matching public key. When set, decryption fails unless the message is signed and the signer key's OpenPGP user ID contains one of these values."
    )
    @PluginProperty(group = "advanced")
    private Property<List<String>> requiredSignerUsers;

    @Override
    public Decrypt.Output run(RunContext runContext) throws Exception {
        Logger logger = runContext.logger();

        var rFrom = URI.create(runContext.render(this.from).as(String.class).orElseThrow());
        var rSignKeys = runContext.render(this.signUsersKey).asList(String.class);
        var rRequiredSignerUsers = runContext.render(this.requiredSignerUsers).asList(String.class);

        if (!rRequiredSignerUsers.isEmpty() && rSignKeys.isEmpty()) {
            throw new PGPException("'requiredSignerUsers' requires 'signUsersKey' to be set as well, so the signer's identity can be verified against a trusted public key");
        }

        boolean signatureRequired = !rSignKeys.isEmpty();
        File outFile = runContext.workingDir().createTempFile().toFile();

        AbstractPgp.addProvider();

        var rPrivateKey = runContext.render(this.privateKey).as(String.class).orElseThrow();
        var rPassphrase = runContext.render(this.privateKeyPassphrase).as(String.class).orElse("").toCharArray();

        var secretKeys = new PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(new ByteArrayInputStream(rPrivateKey.getBytes(StandardCharsets.UTF_8))),
            new JcaKeyFingerprintCalculator()
        );

        List<PGPPublicKeyRingCollection> signerKeyrings = new ArrayList<>();

        if (!rSignKeys.isEmpty()) {
            signerKeyrings = rSignKeys.stream()
                .map(throwFunction(key ->
                {
                    try (
                        InputStream pubKeyIn = PGPUtil.getDecoderStream(
                            new ByteArrayInputStream(key.getBytes(StandardCharsets.UTF_8))
                        )
                    ) {
                        return new PGPPublicKeyRingCollection(pubKeyIn, new JcaKeyFingerprintCalculator());
                    }
                }))
                .filter(Objects::nonNull)
                .toList();
        }

        try (
            InputStream encryptedIn = PGPUtil.getDecoderStream(runContext.storage().getFile(rFrom));
            var fileOut = new BufferedOutputStream(new FileOutputStream(outFile))
        ) {

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

            try (
                InputStream clear = encData.getDataStream(
                    new JcePublicKeyDataDecryptorFactoryBuilder().build(privateKey)
                )
            ) {

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
                    if (signatureRequired) {
                        throw new PGPException("Message is not signed but a signature is required by 'signUsersKey'");
                    }
                    Streams.pipeAll(literal.getInputStream(), fileOut);
                }

                else if (message instanceof PGPOnePassSignatureList sigList) {
                    if (sigList.isEmpty()) {
                        throw new PGPException("No one-pass signature found in the OpenPGP message");
                    }

                    // Only the outermost one-pass signature (the last one applied, first one encountered)
                    // is verified; per RFC 4880 §11.3 it pairs with the LAST entry of the trailing signature list.
                    PGPOnePassSignature sig = sigList.get(0);
                    PGPPublicKeyRing signerKeyRing = findPublicKeyRing(signerKeyrings, sig.getKeyID());
                    PGPPublicKey signerKey = signerKeyRing != null ? signerKeyRing.getPublicKey(sig.getKeyID()) : null;

                    if (signerKey == null) {
                        if (signatureRequired) {
                            throw new PGPException(
                                "No public key matching signer key ID " + Long.toHexString(sig.getKeyID()) + " was found in 'signUsersKey'"
                            );
                        }
                    } else {
                        sig.init(new JcaPGPContentVerifierBuilderProvider(), signerKey);
                    }

                    Object literalObject = plainFactory.nextObject();
                    if (!(literalObject instanceof PGPLiteralData literal)) {
                        throw new PGPException("Expected literal data after the one-pass signature but found " + (literalObject == null ? "end of message" : literalObject.getClass()));
                    }

                    try (InputStream dIn = literal.getInputStream()) {
                        // Streams.pipeAll reads in bulk via read(byte[], int, int), which
                        // FilterInputStream does NOT route through an overridden read(); copy
                        // manually so every byte is also fed into the signature.
                        byte[] buffer = new byte[8192];
                        int read;
                        while ((read = dIn.read(buffer)) >= 0) {
                            if (signerKey != null) {
                                sig.update(buffer, 0, read);
                            }
                            fileOut.write(buffer, 0, read);
                        }
                    }

                    if (signerKey != null) {
                        Object signatureObject = plainFactory.nextObject();
                        if (!(signatureObject instanceof PGPSignatureList signatureList) || signatureList.isEmpty()) {
                            throw new PGPException("No signature packet found to verify the one-pass signature");
                        }

                        PGPSignature matchingSignature = signatureList.get(signatureList.size() - 1);
                        if (!sig.verify(matchingSignature)) {
                            throw new PGPException("Signature verification failed: message content does not match the signature");
                        }

                        if (!rRequiredSignerUsers.isEmpty()) {
                            // User IDs live on the key ring's primary key, not on a signing subkey
                            // (GPG signs with a signing subkey by default, e.g. `gpg --sign`).
                            PGPPublicKey primaryKey = signerKeyRing.getPublicKey();
                            List<String> signerUserIds = new ArrayList<>();
                            (primaryKey != null ? primaryKey : signerKey).getUserIDs().forEachRemaining(signerUserIds::add);

                            // OpenPGP user IDs are commonly "Name (comment) <email>"; match by
                            // substring so a required email still matches the full user ID string.
                            boolean matches = signerUserIds.stream()
                                .anyMatch(userId -> rRequiredSignerUsers.stream().anyMatch(userId::contains));

                            if (!matches) {
                                throw new PGPException(
                                    "Signer user ID(s) " + signerUserIds + " do not match any of the required signer users " + rRequiredSignerUsers
                                );
                            }
                        }
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

    private PGPPublicKeyRing findPublicKeyRing(List<PGPPublicKeyRingCollection> collections, long keyID) {
        for (PGPPublicKeyRingCollection collection : collections) {
            Iterator<PGPPublicKeyRing> rings = collection.getKeyRings();
            while (rings.hasNext()) {
                PGPPublicKeyRing ring = rings.next();
                if (ring.getPublicKey(keyID) != null) {
                    return ring;
                }
            }
        }
        return null;
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(
            title = "URI of decrypted file"
        )
        private final URI uri;
    }
}
