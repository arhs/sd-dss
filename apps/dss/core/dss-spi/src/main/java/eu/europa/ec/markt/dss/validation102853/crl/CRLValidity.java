/*
 * SD-DSS - Digital Signature Services
 *
 * Copyright (C) 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * Developed by: 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * This file is part of the "https://github.com/arhs/sd-dss" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "SD-DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss.validation102853.crl;

import java.security.cert.X509CRL;

import eu.europa.ec.markt.dss.validation102853.CertificateToken;

/**
 * This class encapsulates all information related to the validity of a CRL. It exposes the method {@code isValid} to check the validity.
 * <p/>
 *
 * @author Robert Bielecki
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CRLValidity {

	X509CRL x509CRL = null;

	boolean issuerX509PrincipalMatches = false;
	boolean signatureIntact = false;
	boolean crlSignKeyUsage = false;
	boolean unknownCriticalExtension = true;

	CertificateToken issuerToken = null;

	String signatureInvalidityReason = "";

	/**
	 * This method indicates if the CRL is valid. To be valid the CRL must full fill the following requirements:<p/>
	 * - its signature must be valid,
	 * - the issuer of the certificate for which the CRL is used must match the CRL signing certificate and
	 * - the mandatory key usage must be present.
	 *
	 * @return {@code true} if the CRL is valid {@code false} otherwise.
	 */
	boolean isValid() {

		return issuerX509PrincipalMatches && signatureIntact && crlSignKeyUsage && !unknownCriticalExtension;
	}

	@Override
	public String toString() {
		return "CRLValidity{" +
			  "x509CRL=" + x509CRL +
			  ", issuerX509PrincipalMatches=" + issuerX509PrincipalMatches +
			  ", signatureIntact=" + signatureIntact +
			  ", crlSignKeyUsage=" + crlSignKeyUsage +
			  ", unknownCriticalExtension=" + unknownCriticalExtension +
			  ", issuerToken=" + issuerToken +
			  ", signatureInvalidityReason='" + signatureInvalidityReason + '\'' +
			  '}';
	}
}
