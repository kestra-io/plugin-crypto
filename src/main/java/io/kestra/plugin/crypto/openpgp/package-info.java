@PluginSubGroup(
    title = "OpenPGP",
    description = "This sub-group of plugins contains tasks for encrypting and decrypting files.",
    categories = PluginSubGroup.PluginCategory.TRANSFORMATION,
    categories = {
        PluginSubGroup.PluginCategory.CORE,
        PluginSubGroup.PluginCategory.INFRASTRUCTURE
    }
)
package io.kestra.plugin.crypto.openpgp;

import io.kestra.core.models.annotations.PluginSubGroup;