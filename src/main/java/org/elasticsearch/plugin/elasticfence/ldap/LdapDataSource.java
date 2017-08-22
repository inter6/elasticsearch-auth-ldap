package org.elasticsearch.plugin.elasticfence.ldap;

import lombok.Getter;
import org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsFactory;
import org.apache.directory.api.ldap.codec.standalone.StandaloneLdapApiService;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.directory.ldap.client.api.LdapNetworkConnection;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

import static org.elasticsearch.plugin.elasticfence.Constants.*;

public class LdapDataSource {
    private final static Logger LOG = LogManager.getLogger(LdapDataSource.class);

    static {
        System.setProperty(StandaloneLdapApiService.CONTROLS_LIST, PagedResultsFactory.class.getName());
    }

    @Getter
    private final LdapConnectionConfig config;
    private LdapConnection connection;

    public LdapDataSource(Settings settings, String bindDn, String bindPassword) {
        this.config = config(settings, bindDn, bindPassword);
    }

    public LdapDataSource(LdapConnectionConfig config) {
        this.config = config;
    }

    private LdapConnectionConfig config(Settings settings, String bindDn, String bindPassword) {
        LdapConnectionConfig config = new LdapConnectionConfig();
        config.setLdapHost(settings.get(SETTINGS_LDAP_HOST));
        config.setLdapPort(settings.getAsInt(SETTINGS_LDAP_PORT, 389));
        if (settings.getAsBoolean(SETTINGS_LDAP_SSL, false)) {
            config.setUseSsl(true);
            config.setTrustManagers(new X509TrustManager() {

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    // do nothing !
                    return null;
                }

                @Override
                public void checkServerTrusted(X509Certificate[] arg0, String arg1) {
                    // do nothing !
                }

                @Override
                public void checkClientTrusted(X509Certificate[] arg0, String arg1) {
                    // do nothing !
                }
            });
        }
        config.setName(bindDn);
        config.setCredentials(bindPassword);
        return config;
    }

    public synchronized LdapConnection connection() throws LdapException {
        if (!isConnected()) {
            connect();
        }
        return connection;
    }

    private void connect() throws LdapException {
        if (isConnected()) {
            disconnect();
        }
        try {
            connection = new LdapNetworkConnection(config);
            connection.bind();
        } catch (LdapException e) {
            disconnect();
            throw e;
        }
    }

    private boolean isConnected() {
        return connection != null && connection.isConnected();
    }

    public void disconnect() {
        if (isConnected()) {
            try {
                connection.unBind();
                connection.close();
            } catch (Exception e) {
                LOG.error("ldap connection close error !", e);
            }
        }
        connection = null;
    }
}
