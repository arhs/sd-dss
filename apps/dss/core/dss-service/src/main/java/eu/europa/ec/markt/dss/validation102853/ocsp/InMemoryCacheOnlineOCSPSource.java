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

package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.cert.ocsp.CertificateID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.RevocationToken;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder to retrieve the OCSP response.
 *
 * @version $Revision$ - $Date$
 */

public class InMemoryCacheOnlineOCSPSource extends OnlineOCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(InMemoryCacheOnlineOCSPSource.class);

	/**
	 * This field contains the freshness time unit to be used when dealing with the revocation freshness. The default value is {@code TimeUnit.DAYS}
	 */
	private TimeUnit freshnessTimeUnit = TimeUnit.DAYS;

	/**
	 * This field contains the freshness value of the revocation data expressed in {@code freshnessTimeUnit}. The default value is {@code 1}
	 */
	private long freshnessValue = 1;

	/**
	 * This {@code Map} contains for each {@code X509Certificate} represented by its {@code CertificateID} the {@code Date} of the production of the OCSP response
	 */
	private Map<CertificateID, Date> ocspFreshness = new HashMap<CertificateID, Date>();

	/**
	 * This constructor allows to set a specific {@code DataLoader}.
	 *
	 * @param dataLoader the component that allows to handle the caching mechanism as {@link eu.europa.ec.markt.dss.validation102853.https.FileCacheDataLoader}
	 * @throws DSSNullException in the case of {@code null} parameter value
	 */
	public InMemoryCacheOnlineOCSPSource(final DataLoader dataLoader) {
		super(dataLoader);
	}

	protected void updateCacheIfRefreshed(final CertificateID certificateId, final boolean refresh, final OCSPToken ocspToken) {

		if (refresh) {
			ocspFreshness.put(certificateId, ocspToken.getIssuingTime());
		}
	}

	/**
	 * This method indicates if the cached OCSP response (if any) related to the given {@code certificateId} should be refreshed or not. The {@code freshnessValue} is checked.
	 *
	 * @param certificateId the {@code CertificateID} for which the OCSP response must be found
	 * @return {@code true} if the cached OCSP response should be refreshed, {@code false} otherwise
	 */
	protected boolean shouldCacheBeRefreshed(final CertificateID certificateId) {

		final Date ocspProductionDate = ocspFreshness.get(certificateId);
		return !isFresh(ocspProductionDate);
	}

	@Override
	public boolean isFresh(final RevocationToken revocationToken) {

		final Date issuingTime = revocationToken.getIssuingTime();
		return isFresh(issuingTime);
	}

	private boolean isFresh(final Date issuingTime) {

		if (issuingTime == null) {
			return false;
		}
		final Date now = new Date();
		final long freshness = DSSUtils.getDateDiff(now, issuingTime, freshnessTimeUnit);
		return freshness <= freshnessValue;
	}
}
