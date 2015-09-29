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

package eu.europa.ec.markt.dss.validation102853.policy;

import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * This class represents a signing certificate validity constraints. The validation is composed of:
 * - check of the validity range compared to the current time.
 * - check of the field: ExpiredCertsRevocationInfo in the trusted list.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CertificateExpirationConstraint extends Constraint {

	private static final Logger LOG = LoggerFactory.getLogger(CertificateExpirationConstraint.class);

	/**
	 * This variable stores the notAfter field of the signing certificate.
	 */
	protected Date notAfter;

	/**
	 * This variable stores the notBefore field of the signing certificate.
	 */
	protected Date notBefore;

	/**
	 * This variable stores the ExpiredCertsRevocationInfo extension from the trusted service associated to the certificate.
	 */
	protected Date expiredCertsRevocationInfo;

	/**
	 * This is the See {@link ProcessParameters#getCurrentTime()}
	 */
	protected Date currentTime;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
	 *
	 * @param level the constraint level string.
	 */
	public CertificateExpirationConstraint(final String level) {

		super(level);
	}

	public Date getNotAfter() {
		return notAfter;
	}

	public void setNotAfter(final Date notAfter) {
		this.notAfter = notAfter;
	}

	public Date getNotBefore() {
		return notBefore;
	}

	public void setNotBefore(final Date notBefore) {
		this.notBefore = notBefore;
	}

	public Date getExpiredCertsRevocationInfo() {
		return expiredCertsRevocationInfo;
	}

	public void setExpiredCertsRevocationInfo(final Date expiredCertsRevocationInfo) {
		this.expiredCertsRevocationInfo = expiredCertsRevocationInfo;
	}

	public Date getCurrentTime() {
		return currentTime;
	}

	public void setCurrentTime(final Date currentTime) {
		this.currentTime = currentTime;
	}

	/**
	 * This method carry out the validation of the constraint.
	 *
	 * @return true if the constraint is met, false otherwise.
	 */
	@Override
	public boolean check() {

		if (ignore()) {

			node.addChild(STATUS, IGNORED);
			return true;
		}
		if (inform()) {

			node.addChild(STATUS, INFORMATION);
			addConstraintParameters();
			node.addChild(INFO, null, messageAttributes);
			return true;
		}
		final boolean certValidity = currentTime.compareTo(notBefore) >= 0 && currentTime.compareTo(notAfter) <= 0;
		if (expiredCertsRevocationInfo == null && !certValidity) {

			addConstraintParameters();
			if (warn()) {

				node.addChild(STATUS, WARN);
				conclusion.addWarning(failureMessageTag, messageAttributes);
				return true;
			}
			node.addChild(STATUS, KO);
			conclusion.setIndication(indication, subIndication);
			conclusion.addError(failureMessageTag, messageAttributes);
			return false;
		}
		node.addChild(STATUS, OK);
		if (messageAttributes.size() > 0) {
			node.addChild(INFO, null, messageAttributes);
		}
		if (expiredCertsRevocationInfo != null) {

			final String formatedExpiredCertsRevocationInfo = DSSUtils.formatDate(expiredCertsRevocationInfo);
			node.addChild(INFO).setAttribute(EXPIRED_CERTS_REVOCATION_INFO, formatedExpiredCertsRevocationInfo);
		}
		return true;
	}

	private void addConstraintParameters() {

		final String formatedCurrentTime = DSSUtils.formatDate(currentTime);
		final String formatedNotBefore = DSSUtils.formatDate(notBefore);
		final String formatedNotAfter = DSSUtils.formatDate(notAfter);

		messageAttributes.put(CURRENT_TIME, formatedNotBefore);
		messageAttributes.put(NOT_BEFORE, formatedNotBefore);
		messageAttributes.put(NOT_AFTER, formatedNotAfter);
	}
}

