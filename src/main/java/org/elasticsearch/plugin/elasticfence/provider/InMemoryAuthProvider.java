package org.elasticsearch.plugin.elasticfence.provider;

import org.apache.commons.lang3.StringUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.elasticsearch.plugin.elasticfence.Constants.SETTINGS_ROOT_PASSWORD;
import static org.elasticsearch.plugin.elasticfence.Constants.SETTINGS_ROOT_USERNAME;

public class InMemoryAuthProvider extends AuthProvider {
    private final static Logger LOG = LogManager.getLogger(InMemoryAuthProvider.class);

    private final Map<String, Credentials> map = new HashMap<>();

    private InMemoryAuthProvider() {
    }

    @Override
    public void init(Settings settings) {
        String rootUsername = settings.get(SETTINGS_ROOT_USERNAME);
        String rootPassword = settings.get(SETTINGS_ROOT_PASSWORD);
        if (StringUtils.isNotBlank(rootUsername) && StringUtils.isNotBlank(rootPassword)) {
            add(rootUsername, Credentials.builder()
                    .username(rootUsername)
                    .password(rootPassword)
                    .build());
            LOG.info("regist root user - USER:{}", rootUsername);
        } else {
            throw new IllegalArgumentException("undefiend root user !");
        }
    }

    @Override
    protected Credentials authenticate(String username, String password) {
        Credentials credentials = map.get(username);
        if (credentials == null) {
            return null;
        }
        if (!StringUtils.equals(credentials.getPassword(), password)) {
            return null;
        }

        Date expired = credentials.getExpired();
        if (expired == null) {
            return credentials;
        }
        if (new Date().before(expired)) {
            return credentials;
        } else {
            map.remove(username);
            return null;
        }
    }

    public void add(String username, Credentials credentials) {
        map.put(username, credentials);
    }

    public static InMemoryAuthProvider getInstance() {
        return HOLDER._instance;
    }

    private static class HOLDER {
        private static InMemoryAuthProvider _instance = new InMemoryAuthProvider();
    }
}
