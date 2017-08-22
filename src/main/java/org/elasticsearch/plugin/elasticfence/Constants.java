package org.elasticsearch.plugin.elasticfence;

public interface Constants {
    String SETTINGS_PREFIX = "elasticfence.";

    String SETTINGS_ENABLED = "enabled";

    String SETTINGS_ROOT_USERNAME = "root.username";
    String SETTINGS_ROOT_PASSWORD = "root.password";

    String SETTINGS_LDAP_ENABLED = "ldap.enabled";
    String SETTINGS_LDAP_HOST = "ldap.host";
    String SETTINGS_LDAP_PORT = "ldap.port";
    String SETTINGS_LDAP_SSL = "ldap.ssl";
    String SETTINGS_LDAP_BIND_DN = "ldap.bind.dn";
    String SETTINGS_LDAP_BIND_PASSWORD = "ldap.bind.password";
    String SETTINGS_LDAP_USER_BASE = "ldap.user.base";
    String SETTINGS_LDAP_USER_FILTER = "ldap.user.filter";
    String SETTINGS_LDAP_GROUP_BASE = "ldap.group.base";
    String SETTINGS_LDAP_GROUP_FILTER = "ldap.group.filter";
    String SETTINGS_LDAP_GROUP_CN = "ldap.group.cn";
    String SETTINGS_LDAP_CACHE_ENABLED = "ldap.cache.enabled";
    String SETTINGS_LDAP_CACHE_EXPIRE_SECONDS = "ldap.cache.expire_seconds";

    int LDAP_PAGE_SIZE = 100;
}
