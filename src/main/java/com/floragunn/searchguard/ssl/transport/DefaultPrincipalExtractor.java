/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
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

import org.elasticsearch.SpecialPermission;

public class DefaultPrincipalExtractor implements PrincipalExtractor {

    private static final String mailOID = "1.2.840.113549.1.9.1";
    private static final int oidTokenLen = mailOID.length()+1;
    
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

                final String dn = AccessController.doPrivileged(new PrivilegedAction<String>() {
                    @Override
                    public String run() {                        
                        return sun.security.x509.X500Name.asX500Name(principal).toString();
                    }
                });
                
                int nmStart = dn.toUpperCase().indexOf("EMAILADDRESS=");
                if(nmStart == -1) {
                    mailTokenLen = 2;
                    nmStart = dn.toUpperCase().indexOf("E=");
                }
                
                final String oldMail = retval.substring(indexMailStart+oidTokenLen, retval.indexOf(',', indexMailStart+oidTokenLen));
                final String newMail = dn.substring(nmStart+mailTokenLen, dn.indexOf(',', nmStart+mailTokenLen));
                retval = retval.replaceFirst(oldMail, newMail);
                retval = retval.replaceFirst(mailOID, "EMAILADDRESS");
            }

            return retval;
            
        }

        return null;
    }

}
