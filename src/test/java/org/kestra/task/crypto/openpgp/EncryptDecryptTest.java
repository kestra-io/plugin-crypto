package org.kestra.task.crypto.openpgp;

import com.devskiller.friendly_id.FriendlyId;
import com.google.common.collect.ImmutableMap;
import com.google.common.io.CharStreams;
import io.micronaut.context.ApplicationContext;
import io.micronaut.test.annotation.MicronautTest;
import org.apache.commons.io.IOUtils;
import org.junit.jupiter.api.Test;
import org.kestra.core.runners.RunContext;
import org.kestra.core.storages.StorageInterface;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Objects;
import javax.inject.Inject;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;

@MicronautTest
class EncryptDecryptTest {
    @Inject
    private ApplicationContext applicationContext;

    @Inject
    private StorageInterface storageInterface;

    @Test
    void run() throws Exception {
        RunContext runContext = new RunContext(this.applicationContext, ImmutableMap.of());

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
            new URI("/" + FriendlyId.createFriendlyId()),
            new FileInputStream(file)
        );

        Encrypt encrypt = Encrypt.builder()
            .from(fileStorage.toString())
            .key(contactPublic)
            .signPublicKey(helloPublic)
            .signPrivateKey(helloPrivate)
            .signPassphrase("abc456")
            .signUser("hello@kestra.io")
            .recipients(Collections.singletonList("contact@kestra.io"))
            .build();
        Encrypt.Output encryptOutput = encrypt.run(runContext);

        Decrypt decrypt = Decrypt.builder()
            .from(encryptOutput.getUri().toString())
            .privateKey(contactPrivate)
            .privateKeyPassphrase("abc456")
            .signUsersKey(Collections.singletonList(helloPublic))
            .requiredSignerUsers(Collections.singletonList("hello@kestra.io"))
            .build();
        Decrypt.Output decryptOutput = decrypt.run(runContext);

        assertThat(
            CharStreams.toString(new InputStreamReader(storageInterface.get(decryptOutput.getUri()))),
            is(CharStreams.toString(new InputStreamReader(new FileInputStream(file))))
        );
    }
}
