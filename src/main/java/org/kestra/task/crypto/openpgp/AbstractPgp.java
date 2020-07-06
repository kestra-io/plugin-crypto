package org.kestra.task.crypto.openpgp;

import lombok.*;
import lombok.experimental.SuperBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallbacks;
import org.kestra.core.exceptions.IllegalVariableEvaluationException;
import org.kestra.core.models.tasks.Task;
import org.kestra.core.runners.RunContext;

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
