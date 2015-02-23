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

package eu.europa.ec.markt.dss.validation102853.crl;

import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.https.CommonDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.Protocol;

/**
 * Online CRL repository. This CRL repository implementation will download the CRLs from the given CRL URIs.
 * Note that for the HTTP kind of URLs you can provide dedicated data loader. If the data loader is not provided the standard load from URI is
 * provided. For FTP the standard load from URI is provided. For LDAP kind of URLs an internal implementation using apache-ldap-api is provided.
 *
 * @version $Revision$ - $Date$
 */

public class OnlineCRLSource extends CommonCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(OnlineCRLSource.class);

	/**
	 * If the multiple protocols are available to retrieve the revocation data, then that indicated by this variable is used first.
	 */
	private Protocol preferredProtocol;

	/**
	 * The component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
	 */
	protected DataLoader dataLoader;

	/**
	 * The default constructor. A {@code CommonsDataLoader is created}.
	 */
	public OnlineCRLSource() {

		dataLoader = new CommonDataLoader();
		LOG.trace("+OnlineCRLSource with the default data loader.");
	}

	/**
	 * This constructor allows to set a specific {@code DataLoader}.
	 *
	 * @param dataLoader the component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
	 * @throws DSSNullException in the case of {@code null} parameter value
	 */
	public OnlineCRLSource(final DataLoader dataLoader) throws DSSNullException {

		setDataLoader(dataLoader);
		LOG.trace("+OnlineCRLSource with the specific data loader.");
	}

	/**
	 * This method allows to set the preferred protocol. This parameter is used used when retrieving the CRL to choose the canal.<br/>
	 * Possible values are: http, ldap, ftp
	 *
	 * @param preferredProtocol {@code Protocol} that is used first to retrieve the revocation data
	 */
	public void setPreferredProtocol(final Protocol preferredProtocol) {

		this.preferredProtocol = preferredProtocol;
	}

	/**
	 * Set the DataLoader to use for querying the CRL server
	 *
	 * @param dataLoader the component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
	 * @throws DSSNullException in the case of {@code null} parameter value
	 */
	public void setDataLoader(final DataLoader dataLoader) throws DSSNullException {

		if (dataLoader == null) {
			throw new DSSNullException(DataLoader.class);
		}
		this.dataLoader = dataLoader;
	}

	@Override
	public CRLToken findCrl(final CertificateToken certificateToken) throws DSSException {

		if (certificateToken == null) {
			return null;
		}
		final CertificateToken issuerToken = certificateToken.getIssuerToken();
		if (issuerToken == null) {
			return null;
		}
		final List<String> crlUrls = getCrlUrl(certificateToken, preferredProtocol);
		if (DSSUtils.isEmpty(crlUrls)) {
			return null;
		}
		final DataLoader.DataAndUrl dataAndUrl = downloadCrl(crlUrls);
		if (dataAndUrl == null) {
			return null;
		}
		final X509CRL x509CRL = buildX509Crl(dataAndUrl.data);
		if (x509CRL == null) {
			return null;
		}
		final List<String> dpUrlList = new ArrayList<String>();
		dpUrlList.add(dataAndUrl.urlString);
		final CRLValidity crlValidity = isValidCRL(x509CRL, issuerToken, dpUrlList);
		final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
		crlToken.setSourceURL(dataAndUrl.urlString);
		return crlToken;
	}

	protected X509CRL buildX509Crl(byte[] data) {
		try {

			final X509CRL x509CRL = DSSUtils.loadCRL(data);
			return x509CRL;
		} catch (Exception e) {
			LOG.warn("", e);
			return null;
		}
	}

	/**
	 * Download a CRL from any location with any protocol.
	 *
	 * @param downloadUrls the {@code List} of urls to be used to obtain the revocation data through the CRL canal.
	 * @return {@code X509CRL} or {@code null} if it was not possible to download the CRL
	 */
	private DataLoader.DataAndUrl downloadCrl(final List<String> downloadUrls) {

		try {

			final DataLoader.DataAndUrl dataAndUrl = dataLoader.get(downloadUrls);
			return dataAndUrl;
		} catch (DSSException e) {
			LOG.warn("", e);
		}
		return null;
	}
}
