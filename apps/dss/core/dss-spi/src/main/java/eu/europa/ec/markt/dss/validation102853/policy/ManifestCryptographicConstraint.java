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
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSNotApplicableMethodException;
import eu.europa.ec.markt.dss.validation102853.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;

import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ASCCM_ANS_2;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ASCCM_ANS_4;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ASCCM_ANS_5;

/**
 * This class represents a signature cryptographic constraints and indicates their level: IGNORE, INFORM, WARN, FAIL.
 * <p/>
 * This constraint is composed of:
 * - Encryption algorithm constraint;
 * - Digest algorithm constraint;
 * - Public key size constraint;
 * - Algorithm Expiration date constraint.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ManifestCryptographicConstraint extends Constraint {

	private static final Logger LOG = LoggerFactory.getLogger(ManifestCryptographicConstraint.class);

	/**
	 * This is the container to store all authorised digest algorithms.
	 */
	protected List<String> digestAlgorithms;

	/**
	 * This is the container to store expiration dates of all encryption and digest algorithms.
	 */
	protected Map<String, Date> algorithmExpirationDates;
	/**
	 * This is the See {@link ProcessParameters#getCurrentTime()}
	 */
	protected Date currentTime;
	/**
	 * This is the {@code digestAlgorithm} to check
	 */
	private String digestAlgorithm;

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
	 *
	 * @param level the constraint level string.
	 */
	public ManifestCryptographicConstraint(final String level) {

		super(level);
	}

	/**
	 * This method is not applicable in the context of this class.
	 *
	 * @param value the simple value of the constraint to set.
	 */
	@Override
	public void setValue(final String value) {
		throw new DSSNotApplicableMethodException(getClass());
	}

	public String getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(final String digestAlgorithm) {
		this.digestAlgorithm = RuleUtils.canonicalizeDigestAlgo(digestAlgorithm);
	}

	public void setCurrentTime(final Date currentTime) {
		this.currentTime = currentTime;
	}

	public List<String> getDigestAlgorithms() {
		return digestAlgorithms;
	}

	public void setDigestAlgorithms(final List<String> digestAlgorithms) {
		this.digestAlgorithms = digestAlgorithms;
	}

	public Map<String, Date> getAlgorithmExpirationDates() {
		return algorithmExpirationDates;
	}

	public void setAlgorithmExpirationDates(final Map<String, Date> algorithmExpirationDates) {
		this.algorithmExpirationDates = algorithmExpirationDates;
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
			node.addChild(INFO).setAttribute(DIGEST_ALGORITHM, digestAlgorithm);
			return true;
		}
		// Digest algorithm verification:
		final boolean containsDigestAlgorithm = RuleUtils.contains1(digestAlgorithm, digestAlgorithms);
		if (!containsDigestAlgorithm) {

			final Pair[] pairs = getParametersAnswer2();
			if (fail(ASCCM_ANS_2, pairs)) {
				return false;
			}
		}
		// Algorithm's expiration date verification:
		if (!algorithmExpirationDates.isEmpty()) {

			Date algorithmExpirationDate = algorithmExpirationDates.get(digestAlgorithm);
			if (algorithmExpirationDate == null) {

				final Pair[] pairs = getParametersAnswer4(digestAlgorithm);
				if (fail(ASCCM_ANS_4, pairs)) {
					return false;
				}
			}
			boolean expiredAlgorithm = algorithmExpirationDate == null ? false : algorithmExpirationDate.before(currentTime);
			if (expiredAlgorithm) {

				final Pair[] pairs = getParametersAnswer5(digestAlgorithm, algorithmExpirationDate);
				if (fail(ASCCM_ANS_5, pairs)) {
					return false;
				}
			}
		}
		addOkNode();
		return true;
	}

	private Pair[] getParametersAnswer5(final String algorithm, final Date algorithmExpirationDate) {

		final Pair[] pairs = new Pair[2];
		pairs[0] = new Pair(ALGORITHM, algorithm);
		pairs[1] = new Pair(ALGORITHM_EXPIRATION_DATE, algorithmExpirationDate == null ? "?" : DSSUtils.formatDate(algorithmExpirationDate));
		return pairs;
	}

	private Pair[] getParametersAnswer4(final String algorithm) {

		final Pair[] pairs = new Pair[1];
		pairs[0] = new Pair(ALGORITHM, algorithm);
		return pairs;
	}

	private Pair[] getParametersAnswer2() {

		final Pair[] pairs = new Pair[1];
		pairs[0] = new Pair(DIGEST_ALGORITHM, digestAlgorithm);
		return pairs;
	}

	private boolean fail(final MessageTag messageTag, final Pair[] pairs) {

		if (warn()) {

			addWarning(messageTag, pairs);
			return false;
		}
		addError(messageTag, pairs);
		return true;
	}

	private void addError(final MessageTag messageTag, final Pair[] pairs) {

		node.addChild(STATUS, KO);
		conclusion.setIndication(indication, subIndication);
		final Conclusion.Error error = conclusion.addError(messageTag);
		for (final Pair pair : pairs) {

			error.setAttribute(pair.first, pair.second);
		}
	}

	private void addWarning(final MessageTag messageTag, final Pair[] pairs) {

		node.addChild(STATUS, WARN);
		final Conclusion.Warning warning = conclusion.addWarning(messageTag);
		for (final Pair pair : pairs) {

			warning.setAttribute(pair.first, pair.second);
		}
	}

	public static class Pair {

		public final String first;
		public final String second;

		/**
		 * Constructor for a Pair.
		 *
		 * @param first  the first object in the Pair
		 * @param second the second object in the pair
		 */
		public Pair(String first, String second) {
			this.first = first;
			this.second = second;
		}
	}
}
