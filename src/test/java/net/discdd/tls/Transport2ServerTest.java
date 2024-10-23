package net.discdd.tls;

import io.grpc.ManagedChannel;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class Transport2ServerTest {
    private static final KeyPair serverKeyPair;
    private static final KeyPair clientKeyPair;
    private static final X509Certificate serverCert;
    private static final X509Certificate clientCert;
    private static final X509Certificate badServerCert;
    private static final X509Certificate badClientCert;

    static {
        try {
            Security.addProvider(new BouncyCastleProvider());
            var keyGenerator = KeyPairGenerator.getInstance("Ed25519");
            keyGenerator.initialize(255);
            serverKeyPair = keyGenerator.generateKeyPair();
            clientKeyPair = keyGenerator.generateKeyPair();
            serverCert = DDDTLSUtil.getSelfSignedCertificate(serverKeyPair, DDDTLSUtil.publicKeyToName(serverKeyPair.getPublic()));
            clientCert = DDDTLSUtil.getSelfSignedCertificate(clientKeyPair, DDDTLSUtil.publicKeyToName(clientKeyPair.getPublic()));
            badServerCert = DDDTLSUtil.getSelfSignedCertificate(serverKeyPair, DDDTLSUtil.publicKeyToName(serverKeyPair.getPublic()) + "bad");
            badClientCert = DDDTLSUtil.getSelfSignedCertificate(clientKeyPair, DDDTLSUtil.publicKeyToName(clientKeyPair.getPublic()) + "bad");
        } catch (CertificateException | NoSuchAlgorithmException | OperatorCreationException e) {
            throw new RuntimeException(e);
        }
    }

    private TLSTestGrpc.TLSTestImplBase testServiceImpl = new TLSTestGrpc.TLSTestImplBase() {
        @Override
        public void test(TLSTestProto.TestRequest request, StreamObserver<TLSTestProto.TestResponse> responseObserver) {
            System.out.println("Got certificate: " + NettyServerCertificateInterceptor.CLIENT_CERTIFICATE_KEY.get().getSubjectX500Principal());
            responseObserver.onNext(TLSTestProto.TestResponse.newBuilder().setReply("Hello").build());
            responseObserver.onCompleted();
        }
    };

    @Test
    public void testNettyTLSGrpc() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        var server = DDDNettyTLS.createGrpcServer(serverKeyPair, serverCert, testServiceImpl);
        server.start();
        ManagedChannel channel = null;
        try {
            var stubWithCert = DDDNettyTLS.createGrpcStubWithCertificate(TLSTestGrpc::newBlockingStub, clientKeyPair, "localhost", server.getPort(), clientCert);
            channel = (ManagedChannel) stubWithCert.stub().getChannel();
            var rsp = stubWithCert.stub().test(TLSTestProto.TestRequest.getDefaultInstance());
            System.out.println(rsp.getReply());
            System.out.println(stubWithCert.certificate().join().getSubjectX500Principal());
            System.out.println(serverCert);
        } finally {
            server.shutdown();
            if (channel != null) channel.shutdown();
        }
    }

    @Test
    public void testNettyTLSGrpcBadClientCert() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        var server = DDDNettyTLS.createGrpcServer(serverKeyPair, serverCert, testServiceImpl);
        server.start();
        ManagedChannel channel = null;
        try {
            var stubWithCert = DDDNettyTLS.createGrpcStubWithCertificate(TLSTestGrpc::newBlockingStub, clientKeyPair, "localhost", server.getPort(), badClientCert);
            channel = (ManagedChannel) stubWithCert.stub().getChannel();
            Assertions.assertThrows(StatusRuntimeException.class, () -> {
                var rsp = stubWithCert.stub().test(TLSTestProto.TestRequest.getDefaultInstance());
                System.out.println(rsp.getReply());
                System.out.println(stubWithCert.certificate().join().getSubjectX500Principal());
            });
        } finally {
            server.shutdown();
            if (channel != null) channel.shutdown();
        }
    }

    @Test
    public void testNettyTLSGrpcBadServerCert() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException {
        var server = DDDNettyTLS.createGrpcServer(serverKeyPair, badServerCert, testServiceImpl);
        server.start();
        ManagedChannel channel = null;
        try {
            var stubWithCert = DDDNettyTLS.createGrpcStubWithCertificate(TLSTestGrpc::newBlockingStub, clientKeyPair, "localhost", server.getPort(), clientCert);
            channel = (ManagedChannel) stubWithCert.stub().getChannel();
            Assertions.assertThrows(StatusRuntimeException.class, () -> {
                var rsp = stubWithCert.stub().test(TLSTestProto.TestRequest.getDefaultInstance());
                System.out.println(rsp.getReply());
                System.out.println(stubWithCert.certificate().join().getSubjectX500Principal());
            });
        } finally {
            server.shutdown();
            if (channel != null) channel.shutdown();
        }
    }

}
