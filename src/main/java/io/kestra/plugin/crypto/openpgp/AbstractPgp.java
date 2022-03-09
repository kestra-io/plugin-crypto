package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;

import java.security.Provider;
import java.security.Security;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
abstract public class AbstractPgp extends Task {
    protected static synchronized void addProvider() {
        Provider bc = Security.getProvider("BC");
        if (bc == null) {
            BouncyGPG.registerProvider();
        }
    }

    protected static KeyringConfigCallback keyringConfig(RunContext runContext, String passphrase) throws IllegalVariableEvaluationException {
        if (passphrase != null) {
            return KeyringConfigCallbacks.withPassword(runContext.render(passphrase));
        } else {
            return KeyringConfigCallbacks.withUnprotectedKeys();
        }
    }
}
