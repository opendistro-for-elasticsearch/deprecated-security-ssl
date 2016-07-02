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

package com.floragunn.searchguard.ssl.util;

import java.util.Map.Entry;

import org.elasticsearch.ElasticsearchSecurityException;
import org.elasticsearch.rest.RestRequest;
import org.elasticsearch.transport.TransportMessage;

public class HeaderHelper {

    public static final String SG_CONFIG_PREFIX = "_sg_";
    
    public static void checkSGHeader(final RestRequest request) {
        if (request != null) {

            for (final String header : request.getHeaders()) {
                if (header != null && header.trim().toLowerCase().startsWith(SG_CONFIG_PREFIX.toLowerCase())) {
                    throw new ElasticsearchSecurityException("invalid header found");
                }
            }

            for (final Entry<String, String> header : request.headers()) {
                if (header != null && header.getKey() != null
                        && header.getKey().trim().toLowerCase().startsWith(SG_CONFIG_PREFIX.toLowerCase())) {
                    throw new ElasticsearchSecurityException("invalid header found");
                }
            }
        }
    }

    public static void checkSGHeader(final TransportMessage<?> request) {
        /*if (request != null) {
            for (final String header : request.getHeaders()) {
                if (header != null && header.trim().toLowerCase().startsWith(SG_CONFIG_PREFIX.toLowerCase())) {
                    throw new ElasticsearchSecurityException("invalid header found");
                }
            }
        }*/
    }
}
