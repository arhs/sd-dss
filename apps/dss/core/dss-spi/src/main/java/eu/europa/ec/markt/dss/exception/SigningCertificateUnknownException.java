package eu.europa.ec.markt.dss.exception;

public class SigningCertificateUnknownException extends DSSException {
    public SigningCertificateUnknownException() {
        super("Signing certificate is UNKNOWN according to OCSP responder.");
    }
}
