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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.RevocationToken;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;

/**
 * To speed up the retrieval of the CRL(s) the {@code InMemoryCacheOnlineCRLSource} class allows to define the freshness of CRL. This latter is the period of time during which the
 * CRL can be reused. The freshness is defined as the difference between the thisUpdate field of the CRL and the current time. During the retrieval process the nextUpdate field of
 * the CRL is also checked. If its value is before the current time then the refresh is forced.
 * Note that to be efficient this class must relay on a {@code DataLoader} allowing the caching mechanism as {@link eu.europa.ec.markt.dss.validation102853.https.FileCacheDataLoader}.
 *
 * @author Robert Bielecki
 * @version $Revision$ - $Date$
 */

public class InMemoryCacheOnlineCRLSource extends OnlineCRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(InMemoryCacheOnlineCRLSource.class);

	/**
	 * This field contains the freshness time unit to be used when dealing with the revocation freshness. The default value is {@code TimeUnit.DAYS}
	 */
	private TimeUnit freshnessTimeUnit = TimeUnit.DAYS;

	/**
	 * This field contains the freshness value of the revocation data expressed in {@code freshnessTimeUnit}. The default value is {@code 1}
	 */
	private long freshnessValue = 1;

	/**
	 * This {@code Map} contains for each CRL (represented by its URL) the pair of: thisUpdate and nextUpdate dates
	 */
	private Map<String, DatePair> crlFreshness = new HashMap<String, DatePair>();

	/**
	 * This constructor allows to set a specific {@code DataLoader}.
	 *
	 * @param dataLoader the component that allows to handle the caching mechanism as {@link eu.europa.ec.markt.dss.validation102853.https.FileCacheDataLoader}
	 * @throws DSSNullException in the case of {@code null} parameter value
	 */
	public InMemoryCacheOnlineCRLSource(final DataLoader dataLoader) throws DSSNullException {
		super(dataLoader);
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
		final List<String> crlUrls = getCrlUrl(certificateToken, null);
		if (DSSUtils.isEmpty(crlUrls)) {
			return null;
		}
		for (final String crlUrl : crlUrls) {

			final boolean refresh = shouldRefresh(crlUrl);
			final byte[] crlData = dataLoader.get(crlUrl, refresh);
			if (crlData == null) {
				continue;
			}
			final X509CRL x509Crl = buildX509Crl(crlData);
			if (x509Crl == null) {
				return null;
			}
			final CRLValidity crlValidity = isValidCRL(x509Crl, issuerToken, crlUrls);
			final CRLToken crlToken = new CRLToken(certificateToken, crlValidity);
			crlToken.setSourceURL(crlUrl);
			if (refresh) {
				crlFreshness.put(crlUrl, new DatePair(crlToken.getThisUpdate(), crlToken.getNextUpdate()));
			}
			return crlToken;
		}
		return null;
	}

	/**
	 * This method indicates if the cached CRL (if any) related to the given {@code crlUrl} should be refreshed or not. The nextUpdate of the CRL and the {@code freshnessValue}
	 * are
	 * checked.
	 *
	 * @param crlUrl the {@code String} representation of the CRL's URL
	 * @return {@code true} if the cached CRL should be refreshed, {@code false} otherwise
	 */
	private boolean shouldRefresh(final String crlUrl) {

		final DatePair crlFreshnessInfo = crlFreshness.get(crlUrl);
		if (crlFreshnessInfo != null) {
			return !isFresh(crlFreshnessInfo.nextUpdate, crlFreshnessInfo.thisUpdate);
		}
		return true;
	}

	@Override
	public boolean isFresh(final RevocationToken revocationToken) {

		final Date nextUpdate = revocationToken.getNextUpdate();
		final Date issuingTime = revocationToken.getIssuingTime();
		return isFresh(nextUpdate, issuingTime);
	}

	private boolean isFresh(final Date nextUpdate, final Date issuingTime) {

		final Date now = new Date();
		if (nextUpdate.after(now)) {

			final long freshness = DSSUtils.getDateDiff(now, issuingTime, freshnessTimeUnit);
			if (freshness <= freshnessValue) {
				return true;
			}
		}
		return false;
	}

	/**
	 * The class representing the thisUpdate and nextUpdate fields of a CRL.
	 */
	static class DatePair {

		public final Date thisUpdate;
		public final Date nextUpdate;

		/**
		 * Constructor for a {@code DatePair}.
		 *
		 * @param thisUpdate {@code Date} of the this update
		 * @param nextUpdate {@code Date} of the next update
		 */
		public DatePair(final Date thisUpdate, final Date nextUpdate) {
			this.thisUpdate = thisUpdate;
			this.nextUpdate = nextUpdate;
		}
	}
}