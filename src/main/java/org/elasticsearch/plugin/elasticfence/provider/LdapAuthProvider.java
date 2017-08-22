package org.elasticsearch.plugin.elasticfence.provider;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.time.DateUtils;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.plugin.elasticfence.ldap.LdapAuthService;

import java.util.Date;
import java.util.List;

import static org.elasticsearch.plugin.elasticfence.Constants.*;

public class LdapAuthProvider extends AuthProvider {
    private final static Logger LOG = LogManager.getLogger(LdapAuthProvider.class);

    private boolean enabled;
    private boolean cacheEnabled;
    private int cacheExpireSeconds;
    private LdapAuthService ldapService;

    private LdapAuthProvider() {
    }

    @Override
    public void init(Settings settings) throws Exception {
        enabled = settings.getAsBoolean(SETTINGS_LDAP_ENABLED, false);
        if (!enabled) {
            LOG.info("ldap auth disabled");
            return;
        }
        cacheEnabled = settings.getAsBoolean(SETTINGS_LDAP_CACHE_ENABLED, false);
        cacheExpireSeconds = settings.getAsInt(SETTINGS_LDAP_CACHE_EXPIRE_SECONDS, 3600);

        ldapService = new LdapAuthService(settings);
    }

    @Override
    protected Credentials authenticate(String username, String password) throws Exception {
        if (!enabled) {
            return null;
        }

        List<Entry> entries = ldapService.lookup(username, password);
        if (CollectionUtils.size(entries) != 1) {
            return null;
        }

        Credentials credentials = Credentials.builder()
                .username(username)
                .password(password)
                .build();

        if (cacheEnabled) {
            credentials.setExpired(DateUtils.addSeconds(new Date(), cacheExpireSeconds));
            InMemoryAuthProvider.getInstance().add(username, credentials);
        }
        return credentials;
    }

    public static LdapAuthProvider getInstance() {
        return HOLDER._instance;
    }

    private static class HOLDER {
        private static LdapAuthProvider _instance = new LdapAuthProvider();
    }
}
