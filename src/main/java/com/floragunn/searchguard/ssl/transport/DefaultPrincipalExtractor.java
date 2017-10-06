/*
 * Copyright 2015-2017 floragunn GmbH
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.ssl.transport;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.cert.X509Certificate;

import javax.security.auth.x500.X500Principal;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.SpecialPermission;

public class DefaultPrincipalExtractor implements PrincipalExtractor {

    private static final String EMAILADDRESS = "EMAILADDRESS";
    private static final String EMAILADDRESS_KEY = EMAILADDRESS+"=";
    private static final String mailOID = "1.2.840.113549.1.9.1";
    private static final int oidTokenLen = mailOID.length()+1;
    protected final Logger log = LogManager.getLogger(this.getClass());
    
    @Override
    public String extractPrincipal(X509Certificate x509Certificate, Type type) {
        if (x509Certificate == null) {
            return null;
        }

        final X500Principal principal = x509Certificate.getSubjectX500Principal();

        if (principal != null) {

            String retval = principal.getName();            
            final int indexMailStart = retval.indexOf(mailOID+"=");

            if(indexMailStart > -1) {
                int mailTokenLen = 13;
                
                final SecurityManager sm = System.getSecurityManager();

                if (sm != null) {
                    sm.checkPermission(new SpecialPermission());
                }

                final String dnString = AccessController.doPrivileged(new PrivilegedAction<String>() {
                    @SuppressWarnings("restriction")
                    @Override
                    public String run() {                        
                        return sun.security.x509.X500Name.asX500Name(principal).toString();
                    }
                });
                
                int nmStart = dnString.toUpperCase().indexOf(EMAILADDRESS_KEY);
                if(nmStart == -1) {
                    log.error("Cannot find {} token in {}", EMAILADDRESS_KEY, dnString.toUpperCase());
                    return retval;
                }
                
                final String oldMail = retval.substring(indexMailStart+oidTokenLen, retval.indexOf(',', indexMailStart+oidTokenLen));
                final String newMail = dnString.substring(nmStart+mailTokenLen, dnString.indexOf(',', nmStart+mailTokenLen));
                retval = retval.replaceFirst(oldMail, newMail);
                retval = retval.replaceFirst(mailOID, EMAILADDRESS);
            }

            return retval;
            
        }

        return null;
    }

}
