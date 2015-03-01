package eu.europa.ec.markt.dss.exception;

import java.util.Date;

public class SigningCertificateExpiredException extends DSSException {

    public SigningCertificateExpiredException(Date signingDate, Date notBefore, Date notAfter) {
        super(String.format("Signing Date (%s) is not in certificate validity range (%s, %s).", signingDate.toString(), notBefore.toString(), notAfter.toString()));
    }

}
