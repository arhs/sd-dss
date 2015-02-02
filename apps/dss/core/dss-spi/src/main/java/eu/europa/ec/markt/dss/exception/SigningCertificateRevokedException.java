package eu.europa.ec.markt.dss.exception;

public class SigningCertificateRevokedException extends DSSException {
    public SigningCertificateRevokedException() {
        super("Signing certificate is REVOKED according to OCSP responder.");
    }
}
