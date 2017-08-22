package org.elasticsearch.plugin.elasticfence.ldap;

import org.apache.commons.collections4.CollectionUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.directory.api.ldap.codec.controls.search.pagedSearch.PagedResultsDecorator;
import org.apache.directory.api.ldap.model.cursor.CursorLdapReferralException;
import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapInvalidDnException;
import org.apache.directory.api.ldap.model.message.*;
import org.apache.directory.api.ldap.model.message.controls.PagedResults;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.apache.directory.ldap.client.api.EntryCursorImpl;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.apache.directory.ldap.client.api.LdapConnectionConfig;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.common.settings.Settings;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.elasticsearch.plugin.elasticfence.Constants.*;

public class LdapAuthService {
    private final static Logger LOG = LogManager.getLogger(LdapAuthService.class);

    private final LdapDataSource ldapDataSource;
    private final Dn userBase;
    private final String userFilter;
    private final Dn groupBase;
    private final String groupFilter;
    private final Set<String> groupCNs;

    public LdapAuthService(Settings settings) throws LdapInvalidDnException {
        this.ldapDataSource = new LdapDataSource(settings,
                settings.get(SETTINGS_LDAP_BIND_DN),
                settings.get(SETTINGS_LDAP_BIND_PASSWORD));
        this.userBase = new Dn(settings.get(SETTINGS_LDAP_USER_BASE));
        this.userFilter = settings.get(SETTINGS_LDAP_USER_FILTER);
        this.groupBase = new Dn(settings.get(SETTINGS_LDAP_GROUP_BASE));
        this.groupFilter = settings.get(SETTINGS_LDAP_GROUP_FILTER);
        this.groupCNs = Arrays.stream(StringUtils.split(settings.get(SETTINGS_LDAP_GROUP_CN, ",")))
                .map(String::toUpperCase)
                .collect(Collectors.toSet());
    }

    public List<Entry> lookup(String username, String password) throws Exception {
        SearchRequest searchRequest = new SearchRequestImpl();
        searchRequest.setBase(userBase);
        searchRequest.setFilter(StringUtils.replace(userFilter, "{USERNAME}", username));
        searchRequest.setScope(SearchScope.SUBTREE);

        List<Entry> users = search(searchRequest);
        LOG.info("search user - USERNAME:{} RESULTS:{}", username, CollectionUtils.size(users));

        return users
                .stream()
                .filter(entry -> authenticate(entry.getDn().toString(), password))
                .filter(this::isMemberOf)
                .collect(Collectors.toList());
    }

    private boolean authenticate(String bindDn, String bindPassword) {
        LdapConnectionConfig config = ldapDataSource.getConfig();
        config.setName(bindDn);
        config.setCredentials(bindPassword);

        LdapDataSource ldapDataSource = new LdapDataSource(config);
        try {
            ldapDataSource.connection();
            LOG.info("user bind success - DN:{}", bindDn);
            return true;
        } catch (Exception e) {
            LOG.info("user bind fail ! - DN:{} MSG:{}", bindDn, e.getMessage());
            return false;
        } finally {
            ldapDataSource.disconnect();
        }
    }

    private boolean isMemberOf(Entry entry) {
        if (CollectionUtils.isEmpty(groupCNs)) {
            return true;
        }

        try {
            SearchRequest searchRequest = new SearchRequestImpl();
            searchRequest.setBase(groupBase);
            searchRequest.setFilter(StringUtils.replace(groupFilter, "{MEMBER_DN}", entry.getDn().toString()));
            searchRequest.addAttributes("cn");
            searchRequest.setScope(SearchScope.SUBTREE);

            List<Entry> groups = search(searchRequest);
            LOG.info("search group of user - MEMBER:{} RESULTS:{}", entry.getDn().toString(), CollectionUtils.size(groups));

            return groups
                    .stream()
                    .anyMatch(group -> {
                        try {
                            String cn = group.get("cn").getString();
                            return groupCNs.contains(cn.toUpperCase());
                        } catch (Exception e) {
                            LOG.error("group cn extract fail ! - DN:{}", entry.getDn(), e);
                            return false;
                        }
                    });
        } catch (Exception e) {
            LOG.error("group search fail ! - MEMBER:{}", entry.getDn().toString(), e);
            return false;
        }
    }

    private List<Entry> search(SearchRequest searchRequest) throws Exception {
        List<Entry> entries = new ArrayList<>();

        LdapConnection connection = ldapDataSource.connection();
        PagedResults pagedResults = new PagedResultsDecorator(connection.getCodecService());
        pagedResults.setSize(LDAP_PAGE_SIZE);

        boolean hasUnwillingToPerform = false;
        while (true) {
            EntryCursor cursor = null;
            try {
                searchRequest.addControl(pagedResults);

                cursor = new EntryCursorImpl(connection.search(searchRequest));
                while (cursor.next()) {
                    try {
                        entries.add(cursor.get());
                    } catch (CursorLdapReferralException e) {
                        do {
                            LOG.warn("referral exception ! - CODE:{} MSG:{} INFO:{} RENAME_DN:{} RESOLVE:{}",
                                    e.getResultCode(),
                                    e.getMessage(),
                                    e.getReferralInfo(),
                                    e.getRemainingDn(),
                                    e.getResolvedObject());
                        } while (e.skipReferral());
                    } catch (Exception e) {
                        LOG.error("entry extract error !", e);
                    }
                }

                SearchResultDone result = cursor.getSearchResultDone();
                if (result == null) {
                    break;
                }

                pagedResults = (PagedResults) result.getControl(PagedResults.OID);
                if (result.getLdapResult().getResultCode() == ResultCodeEnum.UNWILLING_TO_PERFORM) {
                    hasUnwillingToPerform = true;
                    break;
                }
            } finally {
                if (cursor != null) {
                    cursor.close();
                }
            }

            if (pagedResults == null || Strings.isEmpty(pagedResults.getCookie())) {
                break;
            }
            pagedResults.setSize(LDAP_PAGE_SIZE);
        }

        if (hasUnwillingToPerform) {
            throw new IllegalStateException("ldap can't handle paging !");
        }
        return entries;
    }
}
