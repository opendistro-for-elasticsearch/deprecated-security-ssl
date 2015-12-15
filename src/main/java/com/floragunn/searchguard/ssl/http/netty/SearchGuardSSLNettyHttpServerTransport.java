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

package com.floragunn.searchguard.ssl.http.netty;

import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.network.NetworkService;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.util.BigArrays;
import org.elasticsearch.http.netty.NettyHttpServerTransport;
import org.jboss.netty.channel.ChannelPipeline;
import org.jboss.netty.channel.ChannelPipelineFactory;
import org.jboss.netty.handler.ssl.SslHandler;

import com.floragunn.searchguard.ssl.SearchGuardKeyStore;

public class SearchGuardSSLNettyHttpServerTransport extends NettyHttpServerTransport {

    private final SearchGuardKeyStore sgks;

    @Inject
    public SearchGuardSSLNettyHttpServerTransport(final Settings settings, final NetworkService networkService, final BigArrays bigArrays,
            final SearchGuardKeyStore sgks) {
        super(settings, networkService, bigArrays);
        this.sgks = sgks;
    }

    @Override
    public ChannelPipelineFactory configureServerChannelPipelineFactory() {
        return new SSLHttpChannelPipelineFactory(this, this.settings, this.detailedErrorsEnabled, sgks);
    }

    protected static class SSLHttpChannelPipelineFactory extends HttpChannelPipelineFactory {

        protected final ESLogger log = Loggers.getLogger(this.getClass());
        private final SearchGuardKeyStore sgks;

        public SSLHttpChannelPipelineFactory(final NettyHttpServerTransport transport, final Settings settings,
                final boolean detailedErrorsEnabled, final SearchGuardKeyStore sgks) {
            super(transport, detailedErrorsEnabled);
            this.sgks = sgks;
        }

        @Override
        public ChannelPipeline getPipeline() throws Exception {
            log.trace("SslHandler configured and added to netty pipeline");

            final ChannelPipeline pipeline = super.getPipeline();
            final SslHandler sslHandler = new SslHandler(sgks.createHTTPSSLEngine());
            sslHandler.setEnableRenegotiation(false);
            pipeline.addFirst("ssl_http", sslHandler);
            pipeline.addBefore("handler", "mutual_ssl", new SearchGuardMutualSSLHandler());
            return pipeline;
        }
    }

}
