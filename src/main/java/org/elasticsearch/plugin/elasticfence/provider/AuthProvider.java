package org.elasticsearch.plugin.elasticfence.provider;

import com.google.common.base.Charsets;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringUtils;
import org.elasticsearch.common.settings.Settings;

public abstract class AuthProvider {

    public void init(Settings settings) throws Exception {
        // if need impl.
    }

    public Credentials authenticate(String authorization) throws Exception {
        String credentials = StringUtils.substringAfter(authorization, "Basic").trim();
        if (StringUtils.isBlank(credentials)) {
            return null;
        }

        String[] tokens = StringUtils.split(new String(Base64.decodeBase64(credentials), Charsets.UTF_8), ":");
        if (ArrayUtils.getLength(tokens) != 2) {
            return null;
        }
        return authenticate(tokens[0], tokens[1]);
    }

    protected abstract Credentials authenticate(String username, String password) throws Exception;
}
