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

import java.security.Principal;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.cert.X509Certificate;

import org.jboss.netty.channel.ChannelHandlerContext;
import org.jboss.netty.channel.MessageEvent;
import org.jboss.netty.channel.SimpleChannelHandler;
import org.jboss.netty.handler.codec.http.DefaultHttpMessage;
import org.jboss.netty.handler.ssl.SslHandler;

public class SearchGuardMutualSSLHandler extends SimpleChannelHandler {

    SearchGuardMutualSSLHandler() {
        super();
    }

    @Override
    public void messageReceived(final ChannelHandlerContext ctx, final MessageEvent e) throws Exception {
        final Object o = e.getMessage();
        if (o instanceof DefaultHttpMessage) {

            final SslHandler sslhandler = (SslHandler) e.getChannel().getPipeline().get("ssl_http");
            Principal principal = null;
            final DefaultHttpMessage request = (DefaultHttpMessage) o;

            try {
                final X509Certificate[] certs = sslhandler.getEngine().getSession().getPeerCertificateChain();

                if (certs != null && certs.length > 0) {
                    principal = sslhandler.getEngine().getSession().getPeerCertificateChain()[0].getSubjectDN();

                    if (principal != null) {
                        request.headers().add("_sg_ssl_principal", principal.getName());
                    }
                }
            } catch (final SSLPeerUnverifiedException e1) {
                // ignore
            }

            request.headers().add("_sg_ssl_protocol", sslhandler.getEngine().getSession().getProtocol());
            request.headers().add("_sg_ssl_cipher", sslhandler.getEngine().getSession().getCipherSuite());
            super.messageReceived(ctx, e);

        } else {
            super.messageReceived(ctx, e);
        }
    }

}
