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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;

/**
 * This source of certificates handles any non trusted certificates. (ex: intermediate certificates used in building certification chain). The {@code CertificateSource} is based
 * on the {@code CertificatePool} which guaranties uniqueness of each certificate. The same {@code CertificatePool} can be shared by many {@code CertificateSource}s.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CommonCertificateSource implements CertificateSource {

	/**
	 * This variable represents the certificate pool with all encapsulated certificates
	 */
	protected CertificatePool certPool;

	/**
	 * The list of all encapsulated certificate tokens. It must be <code>null</code> when instantiating.
	 */
	protected List<CertificateToken> certificateTokens;

	/**
	 * The default constructor to generate a certificates source with an independent certificates pool.
	 */
	public CommonCertificateSource() {
		certPool = new CertificatePool();
	}

	/**
	 * The default constructor with a mandatory shared certificates pool.
	 *
	 * @param certPool shared (external) {@code CertificatePool}
	 */
	public CommonCertificateSource(final CertificatePool certPool) {

		if (certPool == null) {
			throw new DSSNullException(CertificatePool.class);
		}
		this.certPool = certPool;
	}

	@Override
	public CertificateSourceType getCertificateSourceType() {

		return CertificateSourceType.OTHER;
	}

	@Override
	public CertificatePool getCertificatePool() {

		return certPool;
	}

	@Override
	public CertificateToken addCertificate(final X509Certificate x509Certificate) {

		final CertificateToken certificateToken = addCertificate(x509Certificate, null);
		return certificateToken;
	}

	@Override
	public List<CertificateToken> getCertificates() {

		return Collections.unmodifiableList(certificateTokens);
	}

	@Override
	public List<CertificateToken> get(final X500Principal x500Principal) {

		if (x500Principal != null) {

			final List<CertificateToken> localCertificateTokens = new ArrayList<CertificateToken>();
			final List<CertificateToken> poolCertificateTokens = certPool.get(x500Principal);
			for (final CertificateToken certificateToken : poolCertificateTokens) {

				if (certificateTokens.contains(certificateToken)) {
					localCertificateTokens.add(certificateToken);
				}
			}
			return Collections.unmodifiableList(localCertificateTokens);
		}
		return CertificatePool.EMPTY_UNMODIFIABLE_CERTIFICATE_TOKEN_LIST;
	}

	/**
	 * This method is used internally to prevent the addition of a certificate through the {@code CertificatePool}.
	 *
	 * @param x509Certificate {@code X509Certificate} to add to this source
	 * @param serviceInfo     {@code ServiceInfo} associated to the certificate
	 * @return an existing or newly created instance of the {@code CertificateToken}
	 */
	protected CertificateToken addCertificate(final X509Certificate x509Certificate, final ServiceInfo serviceInfo) {

		final CertificateToken certificateToken = certPool.getInstance(x509Certificate, getCertificateSourceType(), serviceInfo);
		if (certificateTokens != null && !certificateTokens.contains(certificateToken)) {
			certificateTokens.add(certificateToken);
		}
		return certificateToken;
	}
}
