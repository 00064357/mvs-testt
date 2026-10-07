package com.epam.tcodata.secure.storage.dal.factory.impl;

import com.microsoft.aad.msal4j.ClientCredentialFactory;
import com.microsoft.aad.msal4j.ClientCredentialParameters;
import com.microsoft.aad.msal4j.ConfidentialClientApplication;
import com.microsoft.aad.msal4j.IAuthenticationResult;
import com.microsoft.aad.msal4j.IClientCredential;
import com.microsoft.azure.keyvault.authentication.KeyVaultCredentials;

import java.util.Collections;

public class CustomKeyValueCredentials extends KeyVaultCredentials {

    private final String clientId;
    private final String clientSecret;

    public CustomKeyValueCredentials(String clientId, String clientSecret) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    @Override
    public String doAuthenticate(String authority, String resource, String scope) {
        try {
            IClientCredential credential = ClientCredentialFactory.createFromSecret(clientSecret);
            ConfidentialClientApplication app =
                    ConfidentialClientApplication.builder(clientId, credential)
                            .authority(authority)
                            .build();
            ClientCredentialParameters params =
                    ClientCredentialParameters.builder(Collections.singleton(resource + "/.default"))
                            .build();
            IAuthenticationResult result = app.acquireToken(params).get();
            return result.accessToken();
        } catch (Exception e) {
            throw new IllegalStateException(e.getMessage(), e);
        }
    }
}
