package net.discdd.tls;

import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import javax.net.ssl.X509ExtendedTrustManager;
import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.EdECPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

public class DDDTLSUtil {
    public static final X509ExtendedTrustManager trustManager = new DDDX509ExtendedTrustManager();

    public static String publicKeyToName(PublicKey key) {
        var edKey = (EdECPublicKey)key;
        var point = edKey.getPoint();
        return new String(Base64.getUrlEncoder().encode(point.getY().toByteArray())).replace("=", "");
    }

    static X509Certificate getSelfSignedCertificate(KeyPair pair, String commonName) throws NoSuchAlgorithmException, OperatorCreationException, CertificateException {
        var csrSigner = new JcaContentSignerBuilder("ED25519").build(pair.getPrivate());
        var csr = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + commonName), pair.getPublic())
                .build(csrSigner);
        var start = Date.from(Instant.now().minus(365, ChronoUnit.DAYS));
        var end = Date.from(Instant.now().plus(365, ChronoUnit.DAYS));
        var cert = new X509v3CertificateBuilder(csr.getSubject(), BigInteger.ONE, start, end,
                csr.getSubject(), csr.getSubjectPublicKeyInfo())
                .build(csrSigner);
        return new JcaX509CertificateConverter().getCertificate(cert);
    }
}
