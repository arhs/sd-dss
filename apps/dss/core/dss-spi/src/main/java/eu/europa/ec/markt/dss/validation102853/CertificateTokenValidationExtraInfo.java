/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.validation102853;

import java.util.Date;

public class CertificateTokenValidationExtraInfo extends TokenValidationExtraInfo {

	private static final String THE_OCSP_SOURCE_IS_NULL = "The OCSP source is null!";
	private static final String AN_EXCEPTION_OCCURRED_DURING_THE_OCSP_RETRIEVAL_PROCESS = "An exception occurred during the OCSP retrieval process: ";
	private static final String THE_CRL_SOURCE_IS_NULL = "The CRL source is null!";
	private static final String THE_CRL_IS_NOT_VALID = "The CRL is not valid!";
	private static final String AN_EXCEPTION_OCCURRED_DURING_THE_CRL_RETRIEVAL_PROCESS = "An exception occurred during the CRL retrieval process: ";
	private static final String OCSP_CHECK_NOT_NEEDED_ID_PKIX_OCSP_NOCHECK_EXTENSION_PRESENT = "OCSP check not needed: id-pkix-ocsp-nocheck extension present.";
	private static final String CERTIFICATE_IS_EXPIRED_BUT_THE_ISSUER_CERTIFICATE_HAS_EXPIRED_CERT_ON_CRL_EXTENSION = "Certificate is expired but the issuer certificate has ExpiredCertOnCRL extension.";
	private static final String CERTIFICATE_IS_EXPIRED_BUT_THE_TSL_EXTENSION_EXPIRED_CERTS_REVOCATION_INFO_IS_PRESENT = "Certificate is expired but the TSL extension 'expiredCertsRevocationInfo' is present: ";

	/**
	 *
	 */
	public void infoOCSPSourceIsNull() {

		if (!validationInfo.contains(THE_OCSP_SOURCE_IS_NULL)) {
			validationInfo.add(THE_OCSP_SOURCE_IS_NULL);
		}
	}

	/**
	 *
	 */
	public void infoOCSPException(final Exception e) {

		if (!validationInfo.contains(AN_EXCEPTION_OCCURRED_DURING_THE_OCSP_RETRIEVAL_PROCESS)) {
			validationInfo.add(AN_EXCEPTION_OCCURRED_DURING_THE_OCSP_RETRIEVAL_PROCESS + e.getMessage());
		}
	}

	/**
	 *
	 */
	public void infoCRLSourceIsNull() {

		if (!validationInfo.contains(THE_CRL_SOURCE_IS_NULL)) {
			validationInfo.add(THE_CRL_SOURCE_IS_NULL);
		}
	}

	/**
	 *
	 */
	public void infoCRLIsNotValid() {

		if (!validationInfo.contains(THE_CRL_IS_NOT_VALID)) {
			validationInfo.add(THE_CRL_IS_NOT_VALID);
		}
	}

	/**
	 *
	 */
	public void infoCRLException(final Exception e) {

		if (!validationInfo.contains(AN_EXCEPTION_OCCURRED_DURING_THE_CRL_RETRIEVAL_PROCESS)) {
			validationInfo.add(AN_EXCEPTION_OCCURRED_DURING_THE_CRL_RETRIEVAL_PROCESS + e.getMessage());
		}
	}

	/**
	 *
	 */
	public void infoOCSPCheckNotNeeded() {

		if (!validationInfo.contains(OCSP_CHECK_NOT_NEEDED_ID_PKIX_OCSP_NOCHECK_EXTENSION_PRESENT)) {
			validationInfo.add(OCSP_CHECK_NOT_NEEDED_ID_PKIX_OCSP_NOCHECK_EXTENSION_PRESENT);
		}
	}

	/**
	 *
	 */
	public void infoExpiredCertOnCRL() {

		if (!validationInfo.contains(CERTIFICATE_IS_EXPIRED_BUT_THE_ISSUER_CERTIFICATE_HAS_EXPIRED_CERT_ON_CRL_EXTENSION)) {
			validationInfo.add(CERTIFICATE_IS_EXPIRED_BUT_THE_ISSUER_CERTIFICATE_HAS_EXPIRED_CERT_ON_CRL_EXTENSION);
		}
	}

	/**
	 *
	 */
	public void infoExpiredCertsRevocationFromDate(final Date expiredCertsRevocationFromDate) {

		final String string = CERTIFICATE_IS_EXPIRED_BUT_THE_TSL_EXTENSION_EXPIRED_CERTS_REVOCATION_INFO_IS_PRESENT + expiredCertsRevocationFromDate;
		if (!validationInfo.contains(string)) {
			validationInfo.add(string);
		}
	}
}
