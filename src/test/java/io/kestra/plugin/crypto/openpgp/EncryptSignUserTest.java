package io.kestra.plugin.crypto.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPairGenerator;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPAlgorithmParameters;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.junit.jupiter.api.Test;

import com.devskiller.friendly_id.FriendlyId;

import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.storages.StorageInterface;
import io.kestra.core.tenant.TenantService;

import jakarta.inject.Inject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

// Reproduces https://github.com/kestra-io/plugin-crypto/issues/133: Encrypt ignored signUser and signed with the first key of signPrivateKey.
@KestraTest
class EncryptSignUserTest {
    private static final String PASSPHRASE = "abc456";

    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private StorageInterface storageInterface;

    private enum Layout {
        NO_KEY_FLAGS,
        SIGNING_SUBKEY,
        NO_SIGNING_KEY
    }

    private record GeneratedKey(PGPSecretKeyRing secretKeyRing, String armoredPublicKey, long signingKeyId) {
    }

    private static Path resource(String name) throws Exception {
        return Path.of(Objects.requireNonNull(EncryptSignUserTest.class.getClassLoader().getResource(name)).toURI());
    }

    private static String readResource(String name) throws Exception {
        return Files.readString(resource(name), StandardCharsets.US_ASCII);
    }

    private static byte[] sourceContent() throws Exception {
        return Files.readAllBytes(resource("application.yml"));
    }

    private static PGPSecretKeyRing parseSecretKeyRing(String armored) throws Exception {
        try (var in = PGPUtil.getDecoderStream(new ByteArrayInputStream(armored.getBytes(StandardCharsets.UTF_8)))) {
            return new PGPSecretKeyRingCollection(in, new JcaKeyFingerprintCalculator()).getKeyRings().next();
        }
    }

    // Armors several secret key rings into one block, as `gpg --export-secret-keys -a` does.
    private static String armorKeyring(PGPSecretKeyRing... rings) throws Exception {
        var byteOut = new ByteArrayOutputStream();
        try (var armoredOut = new ArmoredOutputStream(byteOut)) {
            new PGPSecretKeyRingCollection(List.of(rings)).encode(armoredOut);
        }
        return byteOut.toString(StandardCharsets.US_ASCII);
    }

    private static PGPKeyPair newRsaKeyPair() throws Exception {
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, (PGPAlgorithmParameters) null, keyPairGenerator.generateKeyPair(), new Date());
    }

    private static PGPSignatureSubpacketVector keyFlags(int flags) {
        var subpackets = new PGPSignatureSubpacketGenerator();
        subpackets.setKeyFlags(false, flags);
        return subpackets.generate();
    }

    private static GeneratedKey generateKey(String userId, Layout layout) throws Exception {
        AbstractPgp.addProvider();

        var primary = newRsaKeyPair();
        var digestCalculatorProvider = new JcaPGPDigestCalculatorProviderBuilder().build();
        var keyRingGenerator = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            userId,
            digestCalculatorProvider.get(HashAlgorithmTags.SHA1),
            layout == Layout.NO_KEY_FLAGS ? null : keyFlags(KeyFlags.CERTIFY_OTHER),
            null,
            new JcaPGPContentSignerBuilder(primary.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA256),
            new JcePBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, digestCalculatorProvider.get(HashAlgorithmTags.SHA256))
                .build(PASSPHRASE.toCharArray())
        );

        var signingKeyId = primary.getKeyID();
        if (layout != Layout.NO_KEY_FLAGS) {
            keyRingGenerator.addSubKey(newRsaKeyPair(), keyFlags(KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE), null);
        }
        if (layout == Layout.SIGNING_SUBKEY) {
            var signingSubkey = newRsaKeyPair();
            keyRingGenerator.addSubKey(signingSubkey, keyFlags(KeyFlags.SIGN_DATA), null);
            signingKeyId = signingSubkey.getKeyID();
        }

        var byteOut = new ByteArrayOutputStream();
        try (var armoredOut = new ArmoredOutputStream(byteOut)) {
            keyRingGenerator.generatePublicKeyRing().encode(armoredOut);
        }

        return new GeneratedKey(keyRingGenerator.generateSecretKeyRing(), byteOut.toString(StandardCharsets.US_ASCII), signingKeyId);
    }

    private URI storeSourceFile() throws Exception {
        return storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new ByteArrayInputStream(sourceContent())
        );
    }

    private Encrypt encryptTask(URI source, String signingKeyring, String signUser) throws Exception {
        return Encrypt.builder()
            .from(Property.ofValue(source.toString()))
            .key(Property.ofValue(readResource("pgp/contact-key.pub")))
            .recipients(Property.ofValue(List.of("contact@kestra.io")))
            .signPrivateKey(Property.ofValue(signingKeyring))
            .signPassphrase(Property.ofValue(PASSPHRASE))
            .signUser(Property.ofValue(signUser))
            .build();
    }

    // Decrypts while requiring a signature from expectedSigner, whose public key is the only trusted one.
    private byte[] decryptRequiringSigner(RunContext runContext, URI encrypted, String signerPublicKey, String expectedSigner) throws Exception {
        var decrypt = Decrypt.builder()
            .from(Property.ofValue(encrypted.toString()))
            .privateKey(Property.ofValue(readResource("pgp/contact-key.sec")))
            .privateKeyPassphrase(Property.ofValue(PASSPHRASE))
            .signUsersKey(Property.ofValue(List.of(signerPublicKey)))
            .requiredSignerUsers(Property.ofValue(List.of(expectedSigner)))
            .build();

        try (var decrypted = storageInterface.get(TenantService.MAIN_TENANT, null, decrypt.run(runContext).getUri())) {
            return decrypted.readAllBytes();
        }
    }

    // Opens the encrypted message for the contact recipient and returns the key ID announced by its one-pass signature.
    private long signerKeyId(URI encrypted) throws Exception {
        var recipient = parseSecretKeyRing(readResource("pgp/contact-key.sec"));

        try (var in = PGPUtil.getDecoderStream(storageInterface.get(TenantService.MAIN_TENANT, null, encrypted))) {
            var encryptedData = (PGPPublicKeyEncryptedData) ((PGPEncryptedDataList) new JcaPGPObjectFactory(in).nextObject()).get(0);
            var privateKey = recipient.getSecretKey(encryptedData.getKeyID())
                .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().build(PASSPHRASE.toCharArray()));

            var clear = encryptedData.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().build(privateKey));
            var compressed = (PGPCompressedData) new JcaPGPObjectFactory(clear).nextObject();
            var onePassSignatures = (PGPOnePassSignatureList) new JcaPGPObjectFactory(compressed.getDataStream()).nextObject();
            return onePassSignatures.get(0).getKeyID();
        }
    }

    // Signs as each identity of the same keyring, so whichever key the keyring iterates first, a blind pick fails one run.
    @Test
    void signsWithKeyMatchingSignUserEmail() throws Exception {
        var runContext = runContextFactory.of();
        var hello = parseSecretKeyRing(readResource("pgp/hello-key.sec"));
        var contact = parseSecretKeyRing(readResource("pgp/contact-key.sec"));
        var keyring = armorKeyring(hello, contact);

        for (var signer : Map.of("hello", hello, "contact", contact).entrySet()) {
            var signUser = signer.getKey() + "@kestra.io";
            var encrypted = encryptTask(storeSourceFile(), keyring, signUser).run(runContext).getUri();

            assertThat("signed as " + signUser, signerKeyId(encrypted), is(signer.getValue().getPublicKey().getKeyID()));
            var decrypted = decryptRequiringSigner(runContext, encrypted, readResource("pgp/" + signer.getKey() + "-key.pub"), signUser);
            assertArrayEquals(sourceContent(), decrypted, "signed as " + signUser);
        }
    }

    @Test
    void signsWithKeyMatchingFullSignUserId() throws Exception {
        var runContext = runContextFactory.of();
        var first = generateKey("First Signer <first@kestra.io>", Layout.NO_KEY_FLAGS);
        var second = generateKey("Second Signer <second@kestra.io>", Layout.NO_KEY_FLAGS);
        var keyring = armorKeyring(first.secretKeyRing(), second.secretKeyRing());

        for (var signer : List.of(first, second)) {
            var signUserId = signer.secretKeyRing().getPublicKey().getUserIDs().next();
            var encrypted = encryptTask(storeSourceFile(), keyring, signUserId).run(runContext).getUri();

            assertThat("signed as " + signUserId, signerKeyId(encrypted), is(signer.signingKeyId()));
            var decrypted = decryptRequiringSigner(runContext, encrypted, signer.armoredPublicKey(), signUserId);
            assertArrayEquals(sourceContent(), decrypted, "signed as " + signUserId);
        }
    }

    @Test
    void signUserEmailMatchesIgnoringCase() throws Exception {
        var runContext = runContextFactory.of();
        var keyring = armorKeyring(parseSecretKeyRing(readResource("pgp/hello-key.sec")));

        var encrypted = encryptTask(storeSourceFile(), keyring, "HELLO@Kestra.IO").run(runContext).getUri();

        var decrypted = decryptRequiringSigner(runContext, encrypted, readResource("pgp/hello-key.pub"), "Hello@KESTRA.io");
        assertArrayEquals(sourceContent(), decrypted);
    }

    @Test
    void signsWithSigningSubkeyWhenPrimaryKeyIsCertifyOnly() throws Exception {
        var runContext = runContextFactory.of();
        var signer = generateKey("Subkey Signer <subkey@kestra.io>", Layout.SIGNING_SUBKEY);

        var encrypted = encryptTask(storeSourceFile(), armorKeyring(signer.secretKeyRing()), "subkey@kestra.io").run(runContext).getUri();

        assertThat(signerKeyId(encrypted), is(signer.signingKeyId()));
        assertThat(signer.signingKeyId(), not(signer.secretKeyRing().getPublicKey().getKeyID()));
        var decrypted = decryptRequiringSigner(runContext, encrypted, signer.armoredPublicKey(), "subkey@kestra.io");
        assertArrayEquals(sourceContent(), decrypted);
    }

    @Test
    void keyWithoutSigningCapabilityRejected() throws Exception {
        var runContext = runContextFactory.of();
        var signer = generateKey("No Signer <nosign@kestra.io>", Layout.NO_SIGNING_KEY);
        var encrypt = encryptTask(storeSourceFile(), armorKeyring(signer.secretKeyRing()), "nosign@kestra.io");

        var exception = assertThrows(PGPException.class, () -> encrypt.run(runContext));
        assertThat(exception.getMessage(), containsString("no usable signing key"));
    }

    @Test
    void missingSignUserRejectedWhenSigningKeyIsSet() throws Exception {
        var runContext = runContextFactory.of();
        var encrypt = Encrypt.builder()
            .from(Property.ofValue(storeSourceFile().toString()))
            .key(Property.ofValue(readResource("pgp/contact-key.pub")))
            .recipients(Property.ofValue(List.of("contact@kestra.io")))
            .signPrivateKey(Property.ofValue(readResource("pgp/hello-key.sec")))
            .signPassphrase(Property.ofValue(PASSPHRASE))
            .build();

        var exception = assertThrows(IllegalArgumentException.class, () -> encrypt.run(runContext));
        assertThat(exception.getMessage(), containsString("signUser"));
    }

    @Test
    void unknownSignUserRejected() throws Exception {
        var runContext = runContextFactory.of();
        var keyring = armorKeyring(
            parseSecretKeyRing(readResource("pgp/hello-key.sec")),
            parseSecretKeyRing(readResource("pgp/contact-key.sec"))
        );
        var encrypt = encryptTask(storeSourceFile(), keyring, "unknown@kestra.io");

        var exception = assertThrows(PGPException.class, () -> encrypt.run(runContext));
        assertThat(exception.getMessage(), containsString("unknown@kestra.io"));
        assertThat(exception.getMessage(), containsString("hello@kestra.io"));
    }

    @Test
    void partialSignUserDoesNotMatch() throws Exception {
        var runContext = runContextFactory.of();
        var keyring = armorKeyring(parseSecretKeyRing(readResource("pgp/hello-key.sec")));

        // A substring of the email must not select the key, or "kestra.io" would match every signer.
        var encrypt = encryptTask(storeSourceFile(), keyring, "kestra.io");

        assertThrows(PGPException.class, () -> encrypt.run(runContext));
    }

    @Test
    void ambiguousSignUserRejected() throws Exception {
        var runContext = runContextFactory.of();
        var keyring = armorKeyring(
            generateKey("First <shared@kestra.io>", Layout.NO_KEY_FLAGS).secretKeyRing(),
            generateKey("Second <shared@kestra.io>", Layout.NO_KEY_FLAGS).secretKeyRing()
        );
        var encrypt = encryptTask(storeSourceFile(), keyring, "shared@kestra.io");

        var exception = assertThrows(PGPException.class, () -> encrypt.run(runContext));
        assertThat(exception.getMessage(), containsString("several secret keys"));
    }
}
