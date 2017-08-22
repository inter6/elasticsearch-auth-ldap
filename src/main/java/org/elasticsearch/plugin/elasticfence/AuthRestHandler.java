package org.elasticsearch.plugin.elasticfence;

import com.google.common.net.HttpHeaders;
import org.apache.commons.collections4.CollectionUtils;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.node.NodeClient;
import org.elasticsearch.common.bytes.BytesArray;
import org.elasticsearch.common.bytes.BytesReference;
import org.elasticsearch.common.logging.ESLoggerFactory;
import org.elasticsearch.plugin.elasticfence.provider.AuthProvider;
import org.elasticsearch.plugin.elasticfence.provider.Credentials;
import org.elasticsearch.rest.*;

import java.util.List;

public class AuthRestHandler implements RestHandler {
    private static final Logger LOG = ESLoggerFactory.getLogger("plugin.elasticfence");

    private final RestHandler restHandler;
    private final List<AuthProvider> authProviders;

    public AuthRestHandler(RestHandler restHandler, List<AuthProvider> authProviders) {
        this.restHandler = restHandler;
        this.authProviders = authProviders;
    }

    @Override
    public void handleRequest(RestRequest request, RestChannel channel, NodeClient client) throws Exception {
        if (accept(request)) {
            restHandler.handleRequest(request, channel, client);
        } else {
            channel.sendResponse(new RestResponse() {

                @Override
                public RestStatus status() {
                    return RestStatus.UNAUTHORIZED;
                }

                @Override
                public String contentType() {
                    return "application/json";
                }

                @Override
                public BytesReference content() {
                    return new BytesArray("");
                }
            });
        }
    }

    private boolean accept(RestRequest request) {
        List<String> authValues = request.getAllHeaderValues(HttpHeaders.AUTHORIZATION);
        if (CollectionUtils.size(authValues) != 1) {
            LOG.info("auth fail ! - not found authorization header - REMOTE:{}", request.getRemoteAddress());
            return false;
        }

        Credentials credentials = null;
        for (AuthProvider provider : authProviders) {
            try {
                credentials = provider.authenticate(authValues.get(0));
                if (credentials != null) {
                    break;
                }
            } catch (Exception e) {
                LOG.error("provider error ! - skip this provider - {} REMOTE:{}", provider, request.getRemoteAddress());
            }
        }
        if (credentials != null) {
            LOG.info("auth success - {} REMOTE:{}", credentials, request.getRemoteAddress());
            return true;
        } else {
            LOG.info("auth fail ! - REMOTE:{}", request.getRemoteAddress());
            return false;
        }
    }
}
