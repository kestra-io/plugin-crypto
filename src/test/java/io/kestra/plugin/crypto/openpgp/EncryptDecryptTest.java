package io.kestra.plugin.crypto.openpgp;

import com.devskiller.friendly_id.FriendlyId;
import com.google.common.io.CharStreams;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.property.Property;
import io.kestra.core.runners.RunContext;
import io.kestra.core.runners.RunContextFactory;
import io.kestra.core.storages.StorageInterface;
import io.kestra.core.tenant.TenantService;
import jakarta.inject.Inject;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@KestraTest
class EncryptDecryptTest {
    @Inject
    private RunContextFactory runContextFactory;

    @Inject
    private StorageInterface storageInterface;

    @Test
    void run() throws Exception {
        RunContext runContext = runContextFactory.of();

        String contactPublic = IOUtils.toString(new FileInputStream(new File(Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader()
            .getResource("pgp/contact-key.pub"))
            .toURI())), StandardCharsets.US_ASCII);

        String contactPrivate = IOUtils.toString(new FileInputStream(new File(Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader()
            .getResource("pgp/contact-key.sec"))
            .toURI())), StandardCharsets.US_ASCII);

        String helloPrivate = IOUtils.toString(new FileInputStream(new File(Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader()
            .getResource("pgp/hello-key.sec"))
            .toURI())), StandardCharsets.US_ASCII);

        String helloPublic = IOUtils.toString(new FileInputStream(new File(Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader()
            .getResource("pgp/hello-key.pub"))
            .toURI())), StandardCharsets.US_ASCII);

        File file = new File(Objects.requireNonNull(EncryptDecryptTest.class.getClassLoader()
            .getResource("application.yml"))
            .toURI());

        URI fileStorage = storageInterface.put(
            TenantService.MAIN_TENANT,
            null,
            new URI("/" + FriendlyId.createFriendlyId()),
            new FileInputStream(file)
        );

        Encrypt encrypt = Encrypt.builder()
            .from(Property.ofValue(fileStorage.toString()))
            .key(Property.ofValue(contactPublic))
            .signPublicKey(Property.ofValue(helloPublic))
            .signPrivateKey(Property.ofValue(helloPrivate))
            .signPassphrase(Property.ofValue("abc456"))
            .signUser(Property.ofValue("hello@kestra.io"))
            .recipients(Property.ofValue(Collections.singletonList("contact@kestra.io")))
            .build();
        Encrypt.Output encryptOutput = encrypt.run(runContext);

        Decrypt decrypt = Decrypt.builder()
            .from(Property.ofValue(encryptOutput.getUri().toString()))
            .privateKey(Property.ofValue(contactPrivate))
            .privateKeyPassphrase(Property.ofValue("abc456"))
            .signUsersKey(Property.ofValue(Collections.singletonList(helloPublic)))
            .requiredSignerUsers(Property.ofValue(Collections.singletonList("hello@kestra.io")))
            .build();
        Decrypt.Output decryptOutput = decrypt.run(runContext);

        assertThat(
            CharStreams.toString(new InputStreamReader(storageInterface.get(TenantService.MAIN_TENANT, null, decryptOutput.getUri()))),
            is(CharStreams.toString(new InputStreamReader(new FileInputStream(file))))
        );
    }
}
