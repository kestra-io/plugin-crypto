package io.kestra.plugin.crypto.openpgp;

import java.security.Provider;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import io.kestra.core.models.tasks.Task;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

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

    // Whole user ID or whole email only: a substring match would let "alice@corp.com" match "Not Alice <not-alice@corp.com>".
    protected static boolean matchesUserId(String userId, String expected) {
        return expected.equals(userId) || expected.equalsIgnoreCase(extractEmail(userId));
    }

    private static String extractEmail(String userId) {
        var start = userId.lastIndexOf('<');
        var end = userId.lastIndexOf('>');

        return start >= 0 && end > start ? userId.substring(start + 1, end) : null;
    }
}
