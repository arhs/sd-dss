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

import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ASCCM_ANS_1;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ASCCM_ANS_2;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ASCCM_ANS_3;
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
public class SignatureCryptographicConstraint extends Constraint {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureCryptographicConstraint.class);

	/**
	 * This variable stores the context of the cryptographic constraints.
	 */
	protected String context;

	/**
	 * This variable stores the sub-context of the cryptographic constraints.
	 */
	private final String subContext;

	/**
	 * This is the container to store all authorised encryption algorithms.
	 */
	protected List<String> encryptionAlgorithms;

	/**
	 * This is the container to store all authorised digest algorithms.
	 */
	protected List<String> digestAlgorithms;

	/**
	 * This is the container to store minimum public key size per encryption algorithm.
	 */
	protected Map<String, String> minimumPublicKeySizes;

	/**
	 * This is the container to store expiration dates of all encryption and digest algorithms.
	 */
	protected Map<String, Date> algorithmExpirationDates;

	/**
	 * This is the {@code encryptionAlgorithm} to check
	 */
	private String encryptionAlgorithm;

	/**
	 * This is the {@code digestAlgorithm} to check
	 */
	private String digestAlgorithm;

	/**
	 * This is the {@code keyLength} to check
	 */
	private String keyLength;

	/**
	 * This is the See {@link ProcessParameters#getCurrentTime()}
	 */
	protected Date currentTime;

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

	/**
	 * This is the default constructor. It takes a level of the constraint as parameter. The string representing the level is trimmed and capitalized. If there is no corresponding
	 * {@code Level} then the {@code Level.IGNORE} is set and a warning is logged.
	 *
	 * @param level the constraint level string.
	 */
	public SignatureCryptographicConstraint(final String level, final String context, final String subContext) {

		super(level);
		this.context = context;
		this.subContext = subContext;
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

	public String getEncryptionAlgorithm() {
		return encryptionAlgorithm;
	}

	public void setEncryptionAlgorithm(final String encryptionAlgorithm) {
		this.encryptionAlgorithm = encryptionAlgorithm;
	}

	public String getDigestAlgorithm() {
		return digestAlgorithm;
	}

	public void setDigestAlgorithm(final String digestAlgorithm) {
		this.digestAlgorithm = RuleUtils.canonicalizeDigestAlgo(digestAlgorithm);
	}

	public String getKeyLength() {
		return keyLength;
	}

	public void setKeyLength(final String keyLength) {
		this.keyLength = keyLength;
	}

	public void setCurrentTime(final Date currentTime) {
		this.currentTime = currentTime;
	}

	public List<String> getEncryptionAlgorithms() {
		return encryptionAlgorithms;
	}

	public void setEncryptionAlgorithms(final List<String> encryptionAlgorithms) {
		this.encryptionAlgorithms = encryptionAlgorithms;
	}

	public List<String> getDigestAlgorithms() {
		return digestAlgorithms;
	}

	public void setDigestAlgorithms(final List<String> digestAlgorithms) {
		this.digestAlgorithms = digestAlgorithms;
	}

	public Map<String, String> getMinimumPublicKeySizes() {
		return minimumPublicKeySizes;
	}

	public void setMinimumPublicKeySizes(final Map<String, String> minimumPublicKeySizes) {
		this.minimumPublicKeySizes = minimumPublicKeySizes;
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
			node.addChild(INFO).setAttribute(ENCRYPTION_ALGORITHM, encryptionAlgorithm);
			node.addChild(INFO).setAttribute(DIGEST_ALGORITHM, digestAlgorithm);
			node.addChild(INFO).setAttribute(PUBLIC_KEY_SIZE, keyLength);
			return true;
		}
		// !!! hardcoded
		subIndication = CRYPTO_CONSTRAINTS_FAILURE;
		// Encryption algorithm verification:
		final boolean containsEncryptionAlgorithm = RuleUtils.contains1(encryptionAlgorithm, encryptionAlgorithms);
		if (!containsEncryptionAlgorithm) {

			final Pair[] pairs = getParametersAnswer1();
			if (fail(ASCCM_ANS_1, pairs)) {
				return false;
			}
		}
		// Digest algorithm verification:
		final boolean containsDigestAlgorithm = RuleUtils.contains1(digestAlgorithm, digestAlgorithms);
		if (!containsDigestAlgorithm) {

			final Pair[] pairs = getParametersAnswer2();
			if (fail(ASCCM_ANS_2, pairs)) {
				return false;
			}
		}
		// Minimum public key size verification:
		final String minimumPublicKeySize = minimumPublicKeySizes.get(encryptionAlgorithm);
		int keyLengthInt = 0;
		try {
			keyLengthInt = DSSUtils.isBlank(keyLength) || "?".equals(keyLength) ? 0 : Integer.valueOf(keyLength);
		} catch (NumberFormatException e) {
			LOG.debug("Unknown key length: '" + keyLength + "'");
		}
		final boolean publicKeyBigEnough = minimumPublicKeySize != null && Integer.valueOf(keyLengthInt) >= Integer.valueOf(minimumPublicKeySize);
		if (!publicKeyBigEnough) {

			final Pair[] pairs = getParametersAnswer3(minimumPublicKeySize);
			if (fail(ASCCM_ANS_3, pairs)) {
				return false;
			}
		}
		// Algorithm's expiration date verification:
		// !!! hardcoded
		subIndication = CRYPTO_CONSTRAINTS_FAILURE_NO_POE;
		if (!algorithmExpirationDates.isEmpty()) {

			final String encryptionAlgorithmAndKey = encryptionAlgorithm + keyLength;
			Date algorithmExpirationDate = algorithmExpirationDates.get(encryptionAlgorithmAndKey);
			if (algorithmExpirationDate == null) {

				final Pair[] pairs = getParametersAnswer4(encryptionAlgorithmAndKey);
				if (fail(ASCCM_ANS_4, pairs)) {
					return false;
				}
			}
			boolean expiredAlgorithm = algorithmExpirationDate == null ? false : algorithmExpirationDate.before(currentTime);
			if (expiredAlgorithm) {

				final Pair[] pairs = getParametersAnswer5(encryptionAlgorithmAndKey, algorithmExpirationDate);
				if (fail(ASCCM_ANS_5, pairs)) {
					return false;
				}
			}

			algorithmExpirationDate = algorithmExpirationDates.get(digestAlgorithm);
			if (algorithmExpirationDate == null) {

				final Pair[] pairs = getParametersAnswer4(digestAlgorithm);
				if (fail(ASCCM_ANS_4, pairs)) {
					return false;
				}
			}
			expiredAlgorithm = algorithmExpirationDate == null ? false : algorithmExpirationDate.before(currentTime);
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

		boolean subContextPresent = DSSUtils.isNotBlank(subContext);
		final Pair[] pairs = new Pair[subContextPresent ? 4 : 3];
		pairs[0] = new Pair(ALGORITHM, algorithm);
		pairs[1] = new Pair(CONTEXT, context);
		pairs[2] = new Pair(ALGORITHM_EXPIRATION_DATE, algorithmExpirationDate == null ? "?" : DSSUtils.formatDate(algorithmExpirationDate));
		if (subContextPresent) {
			pairs[3] = new Pair(SUB_CONTEXT, subContext);
		}
		return pairs;
	}

	private Pair[] getParametersAnswer4(final String algorithm) {

		boolean subContextPresent = DSSUtils.isNotBlank(subContext);
		final Pair[] pairs = new Pair[subContextPresent ? 3 : 2];
		pairs[0] = new Pair(ALGORITHM, algorithm);
		pairs[1] = new Pair(CONTEXT, context);
		if (subContextPresent) {
			pairs[2] = new Pair(SUB_CONTEXT, subContext);
		}
		return pairs;
	}

	private Pair[] getParametersAnswer3(final String minimumPublicKeySize) {

		boolean subContextPresent = DSSUtils.isNotBlank(subContext);
		final Pair[] pairs = new Pair[subContextPresent ? 5 : 4];
		pairs[0] = new Pair(ENCRYPTION_ALGORITHM, encryptionAlgorithm);
		pairs[1] = new Pair(PUBLIC_KEY_SIZE, keyLength);
		pairs[2] = new Pair(MINIMUM_PUBLIC_KEY_SIZE, minimumPublicKeySize);
		pairs[3] = new Pair(CONTEXT, context);
		if (subContextPresent) {
			pairs[4] = new Pair(SUB_CONTEXT, subContext);
		}
		return pairs;
	}

	private Pair[] getParametersAnswer2() {

		boolean subContextPresent = DSSUtils.isNotBlank(subContext);
		final Pair[] pairs = new Pair[subContextPresent ? 3 : 2];
		pairs[0] = new Pair(DIGEST_ALGORITHM, digestAlgorithm);
		pairs[1] = new Pair(CONTEXT, context);
		if (subContextPresent) {
			pairs[2] = new Pair(SUB_CONTEXT, subContext);
		}
		return pairs;
	}

	private Pair[] getParametersAnswer1() {

		boolean subContextPresent = DSSUtils.isNotBlank(subContext);
		final Pair[] pairs = new Pair[subContextPresent ? 3 : 2];
		pairs[0] = new Pair(ENCRYPTION_ALGORITHM, encryptionAlgorithm);
		pairs[1] = new Pair(CONTEXT, context);
		if (subContextPresent) {
			pairs[2] = new Pair(SUB_CONTEXT, subContext);
		}
		return pairs;
	}

	private boolean fail(final MessageTag messageTag, final Pair[] pairs) {

		if (warn()) {

			addWarning(messageTag, pairs);
		} else {

			addError(messageTag, pairs);
			return true;
		}
		return false;
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
}
