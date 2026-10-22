package io.kestra.plugin.crypto.openpgp;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.util.Collections;
import java.util.Date;
import java.util.Objects;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketVector;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPKeyPair;
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
import static org.junit.jupiter.api.Assertions.assertThrows;

@KestraTest
class EncryptKeySelectionTest {
    private static final String CONTENT = "hello kestra";

    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private StorageInterface storageInterface;

    @Test
    void encryptsToEd25519KeyEncryptionSubkey() throws Exception {
        var runContext = runContextFactory.of();

        var encrypted = encrypt(runContext, "ed25519");

        assertThat(recipientKeyId(encrypted), is(encryptionSubkey("ed25519").getKeyID()));
        assertThat(decrypt(runContext, encrypted, "ed25519"), is(CONTENT));
    }

    @Test
    void encryptsToRsaEncryptionSubkeyInsteadOfSigningPrimary() throws Exception {
        var runContext = runContextFactory.of();

        var encrypted = encrypt(runContext, "rsa-subkey");

        assertThat(recipientKeyId(encrypted), is(encryptionSubkey("rsa-subkey").getKeyID()));
        assertThat(decrypt(runContext, encrypted, "rsa-subkey"), is(CONTENT));
    }

    @Test
    void encryptsToElGamalSubkeyUnderDsaPrimary() throws Exception {
        var runContext = runContextFactory.of();

        var encrypted = encrypt(runContext, "dsa-elgamal");

        assertThat(recipientKeyId(encrypted), is(encryptionSubkey("dsa-elgamal").getKeyID()));
        assertThat(decrypt(runContext, encrypted, "dsa-elgamal"), is(CONTENT));
    }

    @Test
    void encryptsToKeySelfSignedWithSha1() throws Exception {
        var primary = rsaKeyPair(new Date());
        var keyRingGenerator = new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            "sha1@kestra.io",
            new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1),
            null,
            null,
            new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA1),
            null
        );
        var subkeyPair = rsaKeyPair(new Date());
        keyRingGenerator.addSubKey(subkeyPair, null, null);

        var encrypted = encrypt(keyRingGenerator.generatePublicKeyRing(), "sha1@kestra.io");

        assertThat(recipientKeyId(encrypted), is(subkeyPair.getKeyID()));
    }

    @Test
    void rejectsWeakEncryptionSubkey() throws Exception {
        var signingOnly = new PGPSignatureSubpacketGenerator();
        signingOnly.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        var keyRingGenerator = keyRingGenerator(rsaKeyPair(new Date()), "weak-subkey@kestra.io", signingOnly.generate());
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(512);
        keyRingGenerator.addSubKey(new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, generator.generateKeyPair(), new Date()), null, null);
        var keyRing = keyRingGenerator.generatePublicKeyRing();

        var exception = assertThrows(PGPException.class, () -> encrypt(keyRing, "weak-subkey@kestra.io"));
        assertThat(exception.getMessage(), containsString("No usable encryption key"));
    }

    @Test
    void encryptsToPrimaryKeyWithoutKeyFlags() throws Exception {
        var keyRing = keyRingGenerator(rsaKeyPair(new Date()), "no-flags@kestra.io", null).generatePublicKeyRing();

        var encrypted = Encrypt.builder()
            .from(Property.ofValue(put(CONTENT).toString()))
            .key(Property.ofValue(armor(keyRing)))
            .recipients(Property.ofValue(Collections.singletonList("no-flags@kestra.io")))
            .build()
            .run(runContextFactory.of())
            .getUri();

        assertThat(recipientKeyId(encrypted), is(keyRing.getPublicKey().getKeyID()));
    }

    @Test
    void encryptsToSubkeyWithoutKeyFlagsUnderSigningOnlyPrimary() throws Exception {
        var signingOnly = new PGPSignatureSubpacketGenerator();
        signingOnly.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        var keyRingGenerator = keyRingGenerator(rsaKeyPair(new Date()), "unflagged-subkey@kestra.io", signingOnly.generate());
        var subkeyPair = rsaKeyPair(new Date());
        keyRingGenerator.addSubKey(subkeyPair, null, null);
        var keyRing = keyRingGenerator.generatePublicKeyRing();

        var encrypted = Encrypt.builder()
            .from(Property.ofValue(put(CONTENT).toString()))
            .key(Property.ofValue(armor(keyRing)))
            .recipients(Property.ofValue(Collections.singletonList("unflagged-subkey@kestra.io")))
            .build()
            .run(runContextFactory.of())
            .getUri();

        assertThat(recipientKeyId(encrypted), is(subkeyPair.getKeyID()));
    }

    @Test
    void newerSecondaryUserIdDoesNotOverridePrimaryUserIdFlags() throws Exception {
        var created = new Date(System.currentTimeMillis() - 60_000);
        var primary = rsaKeyPair(created);
        var primaryUserId = new PGPSignatureSubpacketGenerator();
        primaryUserId.setSignatureCreationTime(false, created);
        primaryUserId.setPrimaryUserID(false, true);
        primaryUserId.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
        var keyRing = keyRingGenerator(primary, "primary-uid@kestra.io", primaryUserId.generate()).generatePublicKeyRing();

        var secondaryUserId = new PGPSignatureSubpacketGenerator();
        secondaryUserId.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        keyRing = withUserIdSignature(keyRing, primary, "secondary-uid@kestra.io", PGPSignature.POSITIVE_CERTIFICATION, secondaryUserId.generate());

        var encrypted = encrypt(keyRing, "primary-uid@kestra.io");

        assertThat(recipientKeyId(encrypted), is(primary.getKeyID()));
    }

    @Test
    void revokedUserIdDoesNotGrantEncryptionToSigningOnlyPrimary() throws Exception {
        var created = new Date(System.currentTimeMillis() - 60_000);
        var primary = rsaKeyPair(created);
        var signingOnly = new PGPSignatureSubpacketGenerator();
        signingOnly.setSignatureCreationTime(false, created);
        signingOnly.setPrimaryUserID(false, true);
        signingOnly.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        var keyRing = keyRingGenerator(primary, "signing-only@kestra.io", signingOnly.generate()).generatePublicKeyRing();

        var olderCertification = new PGPSignatureSubpacketGenerator();
        olderCertification.setSignatureCreationTime(false, new Date(created.getTime() + 1_000));
        olderCertification.setKeyFlags(false, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA);
        keyRing = withUserIdSignature(keyRing, primary, "revoked@kestra.io", PGPSignature.POSITIVE_CERTIFICATION, olderCertification.generate());
        keyRing = withUserIdSignature(keyRing, primary, "revoked@kestra.io", PGPSignature.CERTIFICATION_REVOCATION, null);

        var finalKeyRing = keyRing;
        var exception = assertThrows(PGPException.class, () -> encrypt(finalKeyRing, "signing-only@kestra.io"));
        assertThat(exception.getMessage(), containsString("No usable encryption key"));
    }

    @Test
    void rejectsEncryptionSubkeyWithoutBindingSignature() throws Exception {
        PGPPublicKeyRing keyRing;
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(resource("rsa-subkey-key.pub").getBytes(StandardCharsets.US_ASCII)))) {
            keyRing = new PGPPublicKeyRing(in, new JcaKeyFingerprintCalculator());
        }
        var subkey = encryptionSubkey("rsa-subkey");
        var unboundSubkey = subkey;
        for (PGPSignature binding : (Iterable<PGPSignature>) () -> subkey.getSignaturesOfType(PGPSignature.SUBKEY_BINDING)) {
            unboundSubkey = PGPPublicKey.removeCertification(unboundSubkey, binding);
        }
        keyRing = PGPPublicKeyRing.insertPublicKey(keyRing, unboundSubkey);

        var encrypt = Encrypt.builder()
            .from(Property.ofValue(put(CONTENT).toString()))
            .key(Property.ofValue(armor(keyRing)))
            .recipients(Property.ofValue(Collections.singletonList("rsa-subkey@kestra.io")))
            .build();

        var exception = assertThrows(PGPException.class, () -> encrypt.run(runContextFactory.of()));
        assertThat(exception.getMessage(), containsString("No usable encryption key"));
    }

    private URI put(String content) throws Exception {
        return storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new ByteArrayInputStream(content.getBytes(StandardCharsets.UTF_8))
        );
    }

    private static PGPKeyPair rsaKeyPair(Date created) throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return new JcaPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, generator.generateKeyPair(), created);
    }

    private static PGPKeyRingGenerator keyRingGenerator(PGPKeyPair primary, String userId, PGPSignatureSubpacketVector primaryHashedSubpackets) throws Exception {
        return new PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            userId,
            new JcaPGPDigestCalculatorProviderBuilder().build().get(HashAlgorithmTags.SHA1),
            primaryHashedSubpackets,
            null,
            new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA512),
            null
        );
    }

    private static PGPPublicKeyRing withUserIdSignature(PGPPublicKeyRing keyRing, PGPKeyPair primary, String userId, int signatureType, PGPSignatureSubpacketVector hashedSubpackets)
        throws Exception {
        var generator = new PGPSignatureGenerator(
            new JcaPGPContentSignerBuilder(PublicKeyAlgorithmTags.RSA_GENERAL, HashAlgorithmTags.SHA512),
            primary.getPublicKey()
        );
        generator.init(signatureType, primary.getPrivateKey());
        if (hashedSubpackets != null) {
            generator.setHashedSubpackets(hashedSubpackets);
        }
        var signature = generator.generateCertification(userId, primary.getPublicKey());
        var primaryKey = PGPPublicKey.addCertification(keyRing.getPublicKey(), userId, signature);
        return PGPPublicKeyRing.insertPublicKey(keyRing, primaryKey);
    }

    private static String armor(PGPPublicKeyRing keyRing) throws Exception {
        var armored = new ByteArrayOutputStream();
        try (ArmoredOutputStream out = new ArmoredOutputStream(armored)) {
            keyRing.encode(out);
        }
        return armored.toString(StandardCharsets.US_ASCII);
    }

    private URI encrypt(PGPPublicKeyRing keyRing, String recipient) throws Exception {
        return Encrypt.builder()
            .from(Property.ofValue(put(CONTENT).toString()))
            .key(Property.ofValue(armor(keyRing)))
            .recipients(Property.ofValue(Collections.singletonList(recipient)))
            .build()
            .run(runContextFactory.of())
            .getUri();
    }

    private URI encrypt(RunContext runContext, String keyName) throws Exception {
        return Encrypt.builder()
            .from(Property.ofValue(put(CONTENT).toString()))
            .key(Property.ofValue(resource(keyName + "-key.pub")))
            .recipients(Property.ofValue(Collections.singletonList(keyName + "@kestra.io")))
            .build()
            .run(runContext)
            .getUri();
    }

    private String decrypt(RunContext runContext, URI encrypted, String keyName) throws Exception {
        Decrypt.Output output = Decrypt.builder()
            .from(Property.ofValue(encrypted.toString()))
            .privateKey(Property.ofValue(resource(keyName + "-key.sec")))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .build()
            .run(runContext);

        try (InputStream in = storageInterface.get(TenantService.MAIN_TENANT, null, output.getUri())) {
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private long recipientKeyId(URI encrypted) throws Exception {
        try (InputStream in = PGPUtil.getDecoderStream(storageInterface.get(TenantService.MAIN_TENANT, null, encrypted))) {
            var encryptedDataList = (PGPEncryptedDataList) new JcaPGPObjectFactory(in).nextObject();
            return ((PGPPublicKeyEncryptedData) encryptedDataList.get(0)).getKeyID();
        }
    }

    private PGPPublicKey encryptionSubkey(String keyName) throws Exception {
        try (InputStream in = PGPUtil.getDecoderStream(new ByteArrayInputStream(resource(keyName + "-key.pub").getBytes(StandardCharsets.US_ASCII)))) {
            var keyRing = new PGPPublicKeyRing(in, new JcaKeyFingerprintCalculator());
            var keys = keyRing.getPublicKeys();
            keys.next();
            return keys.next();
        }
    }

    private String resource(String name) throws Exception {
        try (InputStream in = Objects.requireNonNull(EncryptKeySelectionTest.class.getClassLoader().getResourceAsStream("pgp/" + name))) {
            return new String(in.readAllBytes(), StandardCharsets.US_ASCII);
        }
    }
}
