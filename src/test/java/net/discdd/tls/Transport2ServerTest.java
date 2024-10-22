package net.discdd.tls;

import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.TlsServerCredentials;
import io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;

public class Transport2ServerTest {
    private static final KeyPair serverKeyPair;
    private static final KeyPair clientKeyPair;
    private ManagedChannel channel;

    private static final X509Certificate serverCert;

    private static final X509Certificate clientCert;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            var keyGenerator = KeyPairGenerator.getInstance("RSA", "BC");
            serverKeyPair = keyGenerator.generateKeyPair();
            clientKeyPair = keyGenerator.generateKeyPair();
            serverCert = getSelfSignedCertificate(serverKeyPair);
            clientCert = getSelfSignedCertificate(clientKeyPair);
        } catch (CertificateException | NoSuchAlgorithmException | OperatorCreationException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static X509Certificate getSelfSignedCertificate(KeyPair pair) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        var csrSigner = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        var csr =
                new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + new String(Base64.getUrlEncoder().encode(pair.getPublic().getEncoded()))), pair.getPublic()).build(
                        csrSigner);
        var start = Date.from(Instant.now().minus(365, ChronoUnit.DAYS));
        var end = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        var cert = new X509v3CertificateBuilder(csr.getSubject(), BigInteger.ONE, start, end,
                csr.getSubject(), csr.getSubjectPublicKeyInfo())
                .build(csrSigner);
        return new JcaX509CertificateConverter().getCertificate(cert);
    }

    @BeforeEach
    public void setUp() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        X509TrustManager myTrustManager = new X509ExtendedTrustManager() {
            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                System.out.println("Checking server " + authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
                System.out.println("Checking server " + authType);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                System.out.println("Checking client " + authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
                System.out.println("Checking server " + authType);
            }

            @Override
            public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                System.out.println("Checking client " + authType);
            }

            @Override
            public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                System.out.println("Checking server " + authType);
            }

            @Override
            public X509Certificate[] getAcceptedIssuers() {
                System.out.println("Getting accepted issuers");
                return new X509Certificate[0];
            }
        };

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setKeyEntry("serverKey", serverKeyPair.getPrivate(), new char[0], new X509Certificate[]{serverCert});
        keyStore.setKeyEntry("clientKey", clientKeyPair.getPrivate(), new char[0], new X509Certificate[]{clientCert});
        var factory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        factory.init(keyStore, new char[0]);
        TlsServerCredentials.newBuilder()
                .keyManager(factory.getKeyManagers())
                .trustManager(myTrustManager)
                .build();
        var sslClientContext = GrpcSslContexts.forClient()
                .clientAuth(ClientAuth.REQUIRE)
                .keyManager(factory)
                .trustManager(myTrustManager)
                .build();
        var sslServerContext = GrpcSslContexts.configure(SslContextBuilder.forServer(serverKeyPair.getPrivate(), serverCert))
                .clientAuth(ClientAuth.REQUIRE)
                .trustManager(myTrustManager)
                .build();
        var server = NettyServerBuilder.forPort(0)
                .sslContext(sslServerContext)
                .addService(new TLSTestGrpc.TLSTestImplBase() {
                    @Override
                    public void test(TLSTestProto.TestRequest request, StreamObserver<TLSTestProto.TestResponse> responseObserver) {
                        responseObserver.onNext(TLSTestProto.TestResponse.newBuilder().setReply("Hello").build());
                        responseObserver.onCompleted();
                    }
                })
                .build();
        server.start();

        channel = NettyChannelBuilder.forAddress("localhost", server.getPort())
                .useTransportSecurity()
                .sslContext(sslClientContext)
                .build();
    }

    @AfterEach
    public void tearDown() {
        if (channel != null) {
            channel.shutdown();
        }
    }

    @Test
    public void testConnectToSslGrpcService() {
        assertNotNull(channel, "Channel should be created");

        var stub = TLSTestGrpc.newBlockingStub(channel);
        var rsp = stub.test(TLSTestProto.TestRequest.getDefaultInstance());
        System.out.println(rsp);
    }
}
