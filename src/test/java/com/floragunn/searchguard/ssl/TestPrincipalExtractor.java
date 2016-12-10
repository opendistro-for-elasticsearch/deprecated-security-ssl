package com.floragunn.searchguard.ssl;

import java.security.cert.X509Certificate;

import com.floragunn.searchguard.ssl.transport.PrincipalExtractor;

public class TestPrincipalExtractor implements PrincipalExtractor {

    private static int transportCount = 0;
    private static int httpCount = 0;
    
    public TestPrincipalExtractor() {
    }

    @Override
    public String extractPrincipal(X509Certificate x509Certificate, Type type) {
        if(type == Type.HTTP) {
            httpCount++;
        }
        
        if(type == Type.TRANSPORT) {
            transportCount++;
        }
        
        return "testdn";
    }

    public static int getTransportCount() {
        return transportCount;
    }

    public static int getHttpCount() {
        return httpCount;
    }
    
    public static void reset() {
       httpCount = 0;
       transportCount = 0;
    }

}
