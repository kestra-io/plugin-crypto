package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.junit.annotations.ExecuteFlow;
import io.kestra.core.junit.annotations.KestraTest;
import io.kestra.core.models.executions.Execution;
import io.kestra.core.models.executions.TaskRun;
import io.kestra.core.models.flows.State;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;

@KestraTest(startRunner = true)
class RunnerTest {
    @Test
    @ExecuteFlow("sanity-checks/all_crypto.yaml")
    void all_crypto(Execution execution) {
        assertThat(execution.getTaskRunList(), hasSize(5));
        assertThat(execution.getState().getCurrent(), is(State.Type.SUCCESS));
    }

    @Test
    @ExecuteFlow("flows/decrypt_wrong_signer.yaml")
    void decrypt_wrong_signer(Execution execution) {
        assertThat(execution.getState().getCurrent(), is(State.Type.FAILED));
        assertThat(failedTaskId(execution), is("decrypt"));
    }

    @Test
    @ExecuteFlow("flows/decrypt_unsigned_message.yaml")
    void decrypt_unsigned_message(Execution execution) {
        assertThat(execution.getState().getCurrent(), is(State.Type.FAILED));
        assertThat(failedTaskId(execution), is("decrypt"));
    }

    @Test
    @ExecuteFlow("flows/decrypt_required_signer_mismatch.yaml")
    void decrypt_required_signer_mismatch(Execution execution) {
        assertThat(execution.getState().getCurrent(), is(State.Type.FAILED));
        assertThat(failedTaskId(execution), is("decrypt"));
    }

    // pins which task actually failed, so a flow broken for an unrelated reason (bad YAML, render
    // error, missing key) doesn't silently pass as "signature verification enforced"
    private static String failedTaskId(Execution execution) {
        return execution.getTaskRunList().stream()
            .filter(taskRun -> taskRun.getState().getCurrent() == State.Type.FAILED)
            .map(TaskRun::getTaskId)
            .findFirst()
            .orElseThrow(() -> new AssertionError("Execution failed but no task run is in a FAILED state"));
    }
}
