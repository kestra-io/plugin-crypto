package io.kestra.plugin.crypto.openpgp;

import java.io.*;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.*;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.SignatureSubpacketTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.*;

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

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
@Schema(
    title = "Encrypt and optionally sign files with OpenPGP",
    description = "Streams a Kestra-stored file through ASCII-armored PGP encryption (AES-256 with integrity) and returns the storage URI. Optionally signs the payload when a private key and passphrase are provided; only the first public key in `key` is used for encryption."
)
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
                    signPrivateKey: "{{ secret('PGP_SIGN_PRIVATE_KEY') }}"
                    signPassphrase: "{{ secret('PGP_SIGN_PASSPHRASE') }}"
                    signUser: signer@kestra.io
                """
        )
    }
)
public class Encrypt extends AbstractPgp implements RunnableTask<Encrypt.Output> {
    @Schema(
        title = "Source file to encrypt",
        description = "Kestra internal storage URI or templated path to the cleartext file."
    )
    @PluginProperty(internalStorageURI = true, group = "source")
    private Property<String> from;

    @Schema(
        title = "Public key for encryption",
        description = "ASCII-armored export such as `gpg --export -a`; the first key ring found is used."
    )
    @PluginProperty(group = "connection")
    private Property<String> key;

    @Schema(
        title = "Recipient identifiers",
        description = "Required metadata for compatibility; values are not validated against the provided key."
    )
    @NotNull
    @PluginProperty(group = "main")
    private Property<List<String>> recipients;

    @Schema(
        title = "Public key used for signature metadata",
        description = "Optional ASCII-armored export; kept for compatibility with legacy plugin expectations."
    )
    @PluginProperty(group = "connection")
    private Property<String> signPublicKey;

    @Schema(
        title = "Private key for signing",
        description = "ASCII-armored secret key used to sign the encrypted payload."
    )
    @ToString.Exclude
    @PluginProperty(secret = true, group = "connection")
    private Property<String> signPrivateKey;

    @Schema(
        title = "Passphrase for signing key",
        description = "Leave empty if the signing key is not protected."
    )
    @ToString.Exclude
    @PluginProperty(secret = true, group = "advanced")
    protected Property<String> signPassphrase;

    @Schema(
        title = "User ID bound to the signature",
        description = "Required when `signPrivateKey` is set. Selects the key in `signPrivateKey` whose user ID equals this value, either the full user ID or its email address (e.g. `signer@kestra.io`, compared ignoring case). Within that key, the newest subkey flagged for signing is used. The task fails if no key, or more than one key, matches."
    )
    @PluginProperty(group = "advanced")
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
        if (this.signPrivateKey != null) {
            var rSignPrivateKey = runContext.render(this.signPrivateKey).as(String.class).orElseThrow();
            var rSignPassphrase = runContext.render(this.signPassphrase).as(String.class).orElse("").toCharArray();
            var rSignUser = runContext.render(this.signUser).as(String.class)
                .filter(user -> !user.isBlank())
                .orElseThrow(() -> new IllegalArgumentException("'signUser' is required when 'signPrivateKey' is set, to select the signing key"));

            PGPSecretKeyRingCollection secretKeyRings;
            try (var privKeyIn = PGPUtil.getDecoderStream(new ByteArrayInputStream(rSignPrivateKey.getBytes(StandardCharsets.UTF_8)))) {
                secretKeyRings = new PGPSecretKeyRingCollection(privKeyIn, new JcaKeyFingerprintCalculator());
            }
            PGPSecretKey signingSecretKey = findSigningKey(findSigningKeyRing(secretKeyRings, rSignUser), rSignUser);
            PGPPrivateKey signingPrivateKey = signingSecretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(rSignPassphrase));

            PGPContentSignerBuilder signerBuilder = new JcaPGPContentSignerBuilder(
                signingSecretKey.getPublicKey().getAlgorithm(), PGPUtil.SHA256
            );

            signatureGenerator = new PGPSignatureGenerator(signerBuilder, signingSecretKey.getPublicKey());
            signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, signingPrivateKey);

        }

        try (
            OutputStream fileOut = new BufferedOutputStream(new FileOutputStream(outFile));
            var armoredOut = new ArmoredOutputStream(fileOut);
            InputStream input = runContext.storage().getFile(rFrom)
        ) {

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
                    try (
                        var literalOut = literalGen.open(
                            compressedOut, PGPLiteralData.BINARY, "data", new Date(), new byte[4096]
                        )
                    ) {

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

    // Several matches fail instead of falling back to keyring order, so the signer is never chosen silently.
    private static PGPSecretKeyRing findSigningKeyRing(PGPSecretKeyRingCollection secretKeyRings, String signUser) throws PGPException {
        var matches = new ArrayList<PGPSecretKeyRing>();
        var availableUserIds = new ArrayList<String>();

        for (PGPSecretKeyRing ring : secretKeyRings) {
            var ringUserIds = new ArrayList<String>();
            ring.getPublicKey().getUserIDs().forEachRemaining(ringUserIds::add);
            availableUserIds.addAll(ringUserIds);

            if (ringUserIds.stream().anyMatch(userId -> matchesUserId(userId, signUser))) {
                matches.add(ring);
            }
        }

        if (matches.isEmpty()) {
            throw new PGPException(
                "No secret key in 'signPrivateKey' has a user ID matching signUser '" + signUser + "'; available user IDs: " + availableUserIds
            );
        }

        if (matches.size() > 1) {
            var keyIds = matches.stream()
                .map(ring -> Long.toHexString(ring.getPublicKey().getKeyID()).toUpperCase())
                .toList();
            throw new PGPException(
                "signUser '" + signUser + "' matches several secret keys in 'signPrivateKey' " + keyIds + "; provide only the intended signing key"
            );
        }

        return matches.getFirst();
    }

    // Prefers the newest key flagged for signing (often a subkey), as GnuPG does; keys without flags fall back to a signing-capable primary.
    private static PGPSecretKey findSigningKey(PGPSecretKeyRing ring, String signUser) throws PGPException {
        var primaryKeyId = ring.getPublicKey().getKeyID();
        var anyKeyFlags = false;
        PGPSecretKey newestSigningKey = null;

        for (PGPSecretKey secretKey : ring) {
            var flags = keyFlags(secretKey.getPublicKey(), primaryKeyId);
            anyKeyFlags |= flags != null;

            var canSign = flags != null && (flags & KeyFlags.SIGN_DATA) != 0;
            var isNewer = newestSigningKey == null
                || secretKey.getPublicKey().getCreationTime().after(newestSigningKey.getPublicKey().getCreationTime());
            if (canSign && !secretKey.isPrivateKeyEmpty() && isNewer) {
                newestSigningKey = secretKey;
            }
        }

        if (newestSigningKey != null) {
            return newestSigningKey;
        }

        var primary = ring.getSecretKey();
        if (!anyKeyFlags && primary.isSigningKey() && !primary.isPrivateKeyEmpty()) {
            return primary;
        }

        throw new PGPException(
            "The secret key for signUser '" + signUser
                + "' has no usable signing key: no key is flagged for signing, or its private part is missing from 'signPrivateKey' (e.g. an export made with 'gpg --export-secret-subkeys' that omits the signing subkey)"
        );
    }

    // Reads the key flags from the newest self-signature (primary key) or binding signature (subkey) issued by the primary key.
    private static Integer keyFlags(PGPPublicKey key, long primaryKeyId) {
        PGPSignature newest = null;

        for (var it = key.getSignatures(); it.hasNext();) {
            var signature = it.next();
            var hashed = signature.getHashedSubPackets();
            var isSelfIssued = signature.getKeyID() == primaryKeyId;
            var hasFlags = hashed != null && hashed.hasSubpacket(SignatureSubpacketTags.KEY_FLAGS);
            if (isSelfIssued && hasFlags && (newest == null || signature.getCreationTime().after(newest.getCreationTime()))) {
                newest = signature;
            }
        }

        return newest == null ? null : newest.getHashedSubPackets().getKeyFlags();
    }

    @Builder
    @Getter
    public static class Output implements io.kestra.core.models.tasks.Output {
        @Schema(
            title = "URI of encrypted file"
        )
        private final URI uri;
    }
}
