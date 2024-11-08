package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.property.Property;
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
public abstract class AbstractPgp extends Task {
    protected static synchronized void addProvider() {
        Provider bc = Security.getProvider("BC");
        if (bc == null) {
            BouncyGPG.registerProvider();
        }
    }

    protected static KeyringConfigCallback keyringConfig(RunContext runContext, Property<String> passphrase) throws IllegalVariableEvaluationException {
        return runContext.render(passphrase)
            .as(String.class)
            .map(KeyringConfigCallbacks::withPassword)
            .orElseGet(KeyringConfigCallbacks::withUnprotectedKeys);
    }
}
