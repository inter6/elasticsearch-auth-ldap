package org.elasticsearch.plugin.elasticfence.provider;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.util.Date;

@Builder
@Getter
@ToString(exclude = "password")
public class Credentials {
    private String username;
    private String password;

    @Setter
    private Date expired;
}
