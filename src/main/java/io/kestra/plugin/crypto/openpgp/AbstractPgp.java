package io.kestra.plugin.crypto.openpgp;

import lombok.*;
import lombok.experimental.SuperBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import io.kestra.core.exceptions.IllegalVariableEvaluationException;
import io.kestra.core.models.tasks.Task;
import io.kestra.core.runners.RunContext;

@SuperBuilder
@ToString
@EqualsAndHashCode
@Getter
@NoArgsConstructor
abstract public class AbstractPgp extends Task {
    protected static KeyringConfigCallback keyringConfig(RunContext runContext, String passphrase) throws IllegalVariableEvaluationException {
        if (passphrase != null) {
            return KeyringConfigCallbacks.withPassword(runContext.render(passphrase));
        } else {
            return KeyringConfigCallbacks.withUnprotectedKeys();
        }
    }
}
