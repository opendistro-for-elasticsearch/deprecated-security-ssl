/*
 * Copyright 2015-2018 _floragunn_ GmbH
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Portions Copyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

package com.amazon.opendistroforelasticsearch.security.ssl.util;


import java.io.FileInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Utils {
    public static <T> T coalesce(T first, T... more) {
        if (first != null) {
            return first;
        }
        
        if(more == null || more.length == 0) {
            return null;
        }
        
        for (int i = 0; i < more.length; i++) {
            T t = more[i];
            if(t != null) {
                return t;
            }
        }
        
        return null;
      }

    public static X509Certificate loadCertificateFromFile(String file) throws Exception {
        if(file == null) {
            return null;
        }

        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        try(FileInputStream is = new FileInputStream(file)) {
            return (X509Certificate) fact.generateCertificate(is);
        }
    }
}
