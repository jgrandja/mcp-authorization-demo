/*
 * Copyright 2020-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.util;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;

/**
 * @author Joe Grandja
 */
public final class AuthorizationServerDiscoverer {
    private final RestClient restClient = RestClient.builder().build();

    public AuthorizationServerDiscoveryResponse discover(String resourceMetadataUri) {
        if (!StringUtils.hasText(resourceMetadataUri)) {
            return null;
        }

        ProtectedResourceMetadata protectedResourceMetadata = this.restClient
                .get()
                .uri(resourceMetadataUri)
                .retrieve()
                .body(ProtectedResourceMetadata.class);

        String authorizationServer = protectedResourceMetadata.authorizationServers().get(0);

        AuthorizationServerMetadata authorizationServerMetadata = this.restClient
                .get()
                .uri(authorizationServer.concat("/.well-known/oauth-authorization-server"))
                .retrieve()
                .body(AuthorizationServerMetadata.class);

        return new AuthorizationServerDiscoveryResponse(protectedResourceMetadata, authorizationServerMetadata);
    }

    public static String parseResourceMetadataUri(String wwwAuthenticateHeader) {
        if (!StringUtils.hasLength(wwwAuthenticateHeader)
                || !StringUtils.startsWithIgnoreCase(wwwAuthenticateHeader, "bearer")) {
            return null;
        }

        String headerValue = wwwAuthenticateHeader.substring("bearer".length()).stripLeading();
        Map<String, String> parameters = new HashMap<>();
        for (String parameter : StringUtils.delimitedListToStringArray(headerValue, ",")) {
            String[] parameterKeyValue = StringUtils.split(parameter, "=");
            if (parameterKeyValue == null || parameterKeyValue.length <= 1) {
                continue;
            }
            parameters.put(parameterKeyValue[0].trim(), parameterKeyValue[1].trim().replace("\"", ""));
        }

        return parameters.get("resource_metadata");
    }

    public record AuthorizationServerDiscoveryResponse(
            ProtectedResourceMetadata protectedResourceMetadata,
            AuthorizationServerMetadata authorizationServerMetadata) {
    }

    public record ProtectedResourceMetadata(
            @JsonProperty("resource") String resource,
            @JsonProperty("authorization_servers") List<String> authorizationServers) {
    }

    public record AuthorizationServerMetadata(
            @JsonProperty("issuer") String issuer,
            @JsonProperty("authorization_endpoint") String authorizationEndpoint,
            @JsonProperty("token_endpoint") String tokenEndpoint,
            @JsonProperty("registration_endpoint") String registrationEndpoint) {
    }

}