# ElasticSearch LDAP Auth Plugin

Elasticsearch user authentication plugin with LDAP.

Performs LDAP authentication on all REST requests.

This plugin is based on [Elasticfence-http-user-auth Plugin](https://github.com/elasticfence/elasticsearch-http-user-auth)


## Build

```
mvn clean package
```

then, created `./jar/elasticfence-${VERSION}.zip`


## Configuration

modify `/etc/elasticsearch/elasticsearch.yml`

```yaml
elasticfence:
  enabled: true  # Enabling/Disabling plugin
  root:  # Root Access
    username: elastic
    password: PASSWORD
  ldap:
    enabled: true  # Enabling/Disabling LDAP auth
    host: 10.0.0.1
    port: 389
    ssl: false
    bind:  # LDAP Login
      dn: cn=admin,cn=Users,dc=inter6,dc=com
      password: PASSWORD
    user:  # User filter
      base: cn=Users,dc=inter6,dc=com
      filter: (&(objectClass=user)(cn={USERNAME}))  # plugin injected to {USERNAME}
    group:  # Group filter
      base: ou=Groups,dc=inter6,dc=com
      filter: (&(objectClass=group)(member={MEMBER_DN}))  # plugin injected to {MEMBER_DN}
      cn: LP00002527  # matching memberOf
    cache:  # Enabling/Disabling cache
      enabled: true
      expire_seconds: 3600
```


## Installation 

```bash
# If previously installed the plugin, delete it.
# elasticsearch-plugin remove elasticfence

elasticsearch-plugin install file:///tmp/elasticfence-${VERSION}.zip

systemctl restart elasticsearch
```
