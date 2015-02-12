package eu.europa.ec.markt.dss.validation102853;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.apache.commons.lang.StringUtils;

public class TestCertificates {
    private static final String BEGIN_CERTIFICATE = "-----BEGIN CERTIFICATE-----";
    private static final String END_CERTIFICATE = "-----END CERTIFICATE-----";
    
    public static final X509Certificate SIGN_CERT_EC = getCertFromPEMFormat("-----BEGIN CERTIFICATE-----\r\n"
            + "MIIEODCCAyCgAwIBAgIQUC5rzCz1TLNRrccUiHvI0TANBgkqhkiG9w0BAQUFADBs\r\n" + "MQswCQYDVQQGEwJFRTEiMCAGA1UECgwZQVMgU2VydGlmaXRzZWVyaW1pc2tlc2t1\r\n"
            + "czEfMB0GA1UEAwwWVEVTVCBvZiBFU1RFSUQtU0sgMjAxMTEYMBYGCSqGSIb3DQEJ\r\n" + "ARYJcGtpQHNrLmVlMB4XDTEzMDYwNDEwNTMwOFoXDTIzMDkwNzEyMDYwOVowgaQx\r\n"
            + "CzAJBgNVBAYTAkVFMRswGQYDVQQKDBJFU1RFSUQgKE1PQklJTC1JRCkxGjAYBgNV\r\n" + "BAsMEWRpZ2l0YWwgc2lnbmF0dXJlMSMwIQYDVQQDDBpURVNUTlVNQkVSLEVDQywx\r\n"
            + "NDIxMjEyODAyOTETMBEGA1UEBAwKVEVTVE5VTUJFUjEMMAoGA1UEKgwDRUNDMRQw\r\n" + "EgYDVQQFEwsxNDIxMjEyODAyOTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABEG8\r\n"
            + "MxwPLh5qmCfkkAPMw+8nKf4cqDETMoWiFiVOGu3cdI61ARLdRQUfa9wpzFDQGtmK\r\n" + "uScHrLE25ZPZWEozK72jggFmMIIBYjAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIG\r\n"
            + "QDCBmQYDVR0gBIGRMIGOMIGLBgorBgEEAc4fAwMBMH0wWAYIKwYBBQUHAgIwTB5K\r\n" + "AEEAaQBuAHUAbAB0ACAAdABlAHMAdABpAG0AaQBzAGUAawBzAC4AIABPAG4AbAB5\r\n"
            + "ACAAZgBvAHIAIAB0AGUAcwB0AGkAbgBnAC4wIQYIKwYBBQUHAgEWFWh0dHA6Ly93\r\n" + "d3cuc2suZWUvY3BzLzAdBgNVHQ4EFgQUWFGTIey4wXdjqSF649GJ1CtYTycwIgYI\r\n"
            + "KwYBBQUHAQMEFjAUMAgGBgQAjkYBATAIBgYEAI5GAQQwHwYDVR0jBBgwFoAUQbb+\r\n" + "xbGxtFMTjPr6YtA0bW0iNAowRQYDVR0fBD4wPDA6oDigNoY0aHR0cDovL3d3dy5z\r\n"
            + "ay5lZS9yZXBvc2l0b3J5L2NybHMvdGVzdF9lc3RlaWQyMDExLmNybDANBgkqhkiG\r\n" + "9w0BAQUFAAOCAQEATozsaw/Ha11N9YgPEyA0tvAR/59yusESFvg9AHhLVyH0Cq+3\r\n"
            + "LJUChnm21mwQ4WS2lMZY4vGieFKVU5w0LQE2QYAgxPuzrKWut+zSsS6O4YapE54j\r\n" + "P0IspSmeLZi2Q7/fqdfciuyJpDXCY/7xmh9uE1vpbEcNvglhIZlM73rcgh8L2jvL\r\n"
            + "hxhRdiltgNUESC43CvuARTWJ1fcN6nPHe1ekx+KBL8RBelbmGMViQhkfCOatrM61\r\n" + "sUJhtGZs/hYxnv1uPyR2pf3xxPSftxdnjNnol6YOBQU7OXcpKeYd2Xd8OI5PKu+d\r\n"
            + "iE0QGTzhRpcKHL90URC2Ac1t1BqHF+vnrh4Mbw==\r\n" + "-----END CERTIFICATE-----\r\n");

    

    public static X509Certificate getCertFromPEMFormat(String pemCert) {
        try {
            return getCertFromBytes(reformatPemString(pemCert).getBytes());
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }

    public static String reformatPemString(String pemCert) {
        pemCert = StringUtils.trim(pemCert).replace("\n", "").replace("\r", "");
        pemCert = StringUtils.removeEnd(StringUtils.removeStart(pemCert, BEGIN_CERTIFICATE), END_CERTIFICATE);
        pemCert = StringUtils.deleteWhitespace(pemCert);
        return BEGIN_CERTIFICATE + "\n" + pemCert + "\n" + END_CERTIFICATE;
    }

    public static X509Certificate getCertFromBytes(byte[] cert) throws CertificateException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(cert));
    }

}
