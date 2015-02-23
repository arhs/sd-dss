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

import java.io.Serializable;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;

/**
 * The validation of a certificate requires to access many different certificates from multiple sources (Trusted List, Trust
 * Store, the signature itself). This interface provides an abstraction for accessing certificates, regardless of the
 * source.
 *
 * @version $Revision: 1846 $ - $Date: 2013-04-04 17:46:44 +0200 (Thu, 04 Apr 2013) $
 */

public interface CertificateSource extends Serializable {

	/**
	 * @return the {@code CertificateSourceType} associated to the implementation class
	 */
	public CertificateSourceType getCertificateSourceType();

	/**
	 * This method return the {@link CertificatePool} encapsulated by the source.
	 */
	public CertificatePool getCertificatePool();

	/**
	 * Retrieves the unmodifiable list of all certificate tokens from this source.
	 *
	 * @return an unmodifiable {@code List} of all {@code CertificateToken}s from this source
	 */
	List<CertificateToken> getCertificates();

	/**
	 * This method adds an external certificate to the encapsulated pool and to the source. If the certificate is already present in the pool its
	 * source type is associated to the token.
	 *
	 * @param x509Certificate {@code X509Certificate} to add to this source
	 * @return an existing or newly created instance of the {@code CertificateToken}
	 */
	public CertificateToken addCertificate(final X509Certificate x509Certificate);

	/**
	 * This method returns an unmodifiable {@code List} of {@code CertificateToken}(s) corresponding to the given subject distinguished name.
	 * The search is performed at the level of {@code CertificateSource} and not at the level of the {@code CertificateSource} (The same {@code CertificatePool} can be shared by
	 * many sources and therefore its content can be different from the content of the {@code CertificateSource}.
	 *
	 * @param x500Principal subject distinguished names of the certificate to find
	 * @return an unmodifiable {@code List} of {@code CertificateToken}s or if no match is found an empty unmodifiable list
	 */
	public List<CertificateToken> get(final X500Principal x500Principal);
}
