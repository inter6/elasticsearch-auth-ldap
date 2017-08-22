package org.elasticsearch.plugin.elasticfence;

import com.google.common.collect.ImmutableList;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.settings.Setting;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.concurrent.ThreadContext;
import org.elasticsearch.plugin.elasticfence.provider.AuthProvider;
import org.elasticsearch.plugin.elasticfence.provider.InMemoryAuthProvider;
import org.elasticsearch.plugin.elasticfence.provider.LdapAuthProvider;
import org.elasticsearch.plugins.ActionPlugin;
import org.elasticsearch.plugins.Plugin;
import org.elasticsearch.rest.RestHandler;

import java.util.Arrays;
import java.util.List;
import java.util.function.UnaryOperator;

import static org.elasticsearch.plugin.elasticfence.Constants.*;

public class ElasticfencePlugin extends Plugin implements ActionPlugin {
    private final static Logger LOG = LogManager.getLogger(ElasticfencePlugin.class);

    private final Settings settings;

    @Inject
    public ElasticfencePlugin(Settings settings) {
        this.settings = settings;
        LOG.info("loading elasticfence plugin...");
    }

    @Override
    public UnaryOperator<RestHandler> getRestHandlerWrapper(ThreadContext threadContext) {
        Settings pluginSettings = settings.getByPrefix(SETTINGS_PREFIX);
        if (!pluginSettings.getAsBoolean(SETTINGS_ENABLED, false)) {
            LOG.warn("elasticfence plugin is disabled");
            return null;
        }

        List<AuthProvider> authProviders = ImmutableList.<AuthProvider>builder()
                .add(InMemoryAuthProvider.getInstance())
                .add(LdapAuthProvider.getInstance())
                .build();
        for (AuthProvider provider : authProviders) {
            try {
                provider.init(pluginSettings);
            } catch (Exception e) {
                throw new IllegalStateException("error occurred during initialization of elasticfence !", e);
            }
        }

        LOG.info("elasticfence plugin is enabled");
        return restHandler -> new AuthRestHandler(restHandler, authProviders);
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
                Setting.boolSetting(SETTINGS_PREFIX + SETTINGS_ENABLED, Boolean.FALSE, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_ROOT_USERNAME, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_ROOT_PASSWORD, Setting.Property.NodeScope),
                Setting.boolSetting(SETTINGS_PREFIX + SETTINGS_LDAP_ENABLED, Boolean.FALSE, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_HOST, Setting.Property.NodeScope),
                Setting.intSetting(SETTINGS_PREFIX + SETTINGS_LDAP_PORT, 389, Setting.Property.NodeScope),
                Setting.boolSetting(SETTINGS_PREFIX + SETTINGS_LDAP_SSL, Boolean.FALSE, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_BIND_DN, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_BIND_PASSWORD, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_USER_BASE, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_USER_FILTER, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_GROUP_BASE, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_GROUP_FILTER, Setting.Property.NodeScope),
                Setting.simpleString(SETTINGS_PREFIX + SETTINGS_LDAP_GROUP_CN, Setting.Property.NodeScope),
                Setting.boolSetting(SETTINGS_PREFIX + SETTINGS_LDAP_CACHE_ENABLED, Boolean.FALSE, Setting.Property.NodeScope),
                Setting.intSetting(SETTINGS_PREFIX + SETTINGS_LDAP_CACHE_EXPIRE_SECONDS, 3600, Setting.Property.NodeScope)
        );
    }
}
