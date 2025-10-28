package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.models.tasks.Task;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
public abstract class AbstractPgp extends Task {
    protected static synchronized void addProvider() {
        Provider bc = Security.getProvider("BC");
        if (bc == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }
}
