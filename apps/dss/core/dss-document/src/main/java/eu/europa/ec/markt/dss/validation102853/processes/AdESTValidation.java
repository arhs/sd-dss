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

package eu.europa.ec.markt.dss.validation102853.processes;

import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.validation102853.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.policy.BasicValidationProcessValidConstraint;
import eu.europa.ec.markt.dss.validation102853.policy.Constraint;
import eu.europa.ec.markt.dss.validation102853.policy.ElementNumberConstraint;
import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.policy.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;

import static eu.europa.ec.markt.dss.validation102853.TimestampType.ARCHIVE_TIMESTAMP;
import static eu.europa.ec.markt.dss.validation102853.TimestampType.SIGNATURE_TIMESTAMP;
import static eu.europa.ec.markt.dss.validation102853.TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP;
import static eu.europa.ec.markt.dss.validation102853.TimestampType.VALIDATION_DATA_TIMESTAMP;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IMIDF;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IMIDF_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IMIVC;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IMIVC_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IRTPTBST;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IRTPTBST_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_ISTPTDABST;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_ISTPTDABST_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_ITVPC;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_ITVPC_ANS_2;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_ITVPC_INFO_1;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_ROBVPIIC;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_VFDTAOCST_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_1;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_1_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_2;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_2_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_DNCTCVP;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_DNCTCVP_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_DNSTCVP;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_DNSTCVP_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.BBB_SAV_ISQPSTP;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.EMPTY;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_ASTPTCT;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_ASTPTCT_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_IBSTAIDOSC;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_IBSTAIDOSC_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_ISCNVABST;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_ISCNVABST_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_WACRABST;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.TSV_WACRABST_ANS;

/**
 * This class implements:<br>
 * <p/>
 * 8 Validation Process for AdES-T
 * <p/>
 * 8.1 Description<br>
 * <p/>
 * An AdES-T signature is built on BES or EPES signature and incorporates trusted time associated to the signature. The
 * trusted time may be provided by two different means:
 * <p/>
 * • A signature time-stamp unsigned property/attribute added to the electronic signature.
 * <p/>
 * • A time mark of the electronic signature provided by a trusted service provider.
 * <p/>
 * This clause describes a validation process for AdES-T signatures.
 *
 * @author bielecro
 */
public class AdESTValidation extends BasicValidationProcess implements Indication, SubIndication, NodeName, NodeValue, ExceptionMessage {

	private static final Logger LOG = LoggerFactory.getLogger(AdESTValidation.class);

	// Primary inputs

	protected ProcessParameters context;

	/**
	 * See {@link eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters#getValidationPolicy()}
	 *
	 * @return
	 */
	private ValidationPolicy validationPolicy;

	// Secondary inputs

	/**
	 * See {@link eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters#getBvXmlDom()}
	 *
	 * @return
	 */
	private XmlDom basicValidationXmlDom;

	private XmlDom timestampValidationXmlDom; // Basic Building Blocks for timestamps

	private XmlDom bvpConclusionXmlDom;
	private String bvpIndication;
	private String bvpSubIndication;

	/**
	 * This node is used to add the constraint nodes.
	 */
	private XmlNode signatureXmlNode;

	/**
	 * Represents the {@code XmlDom} of the signature currently being validated
	 */
	private XmlDom signatureXmlDom;

	/**
	 * Represents the identifier of the signature currently being validated
	 */
	private String signatureId;

	/**
	 * Denotes the earliest time when it can be proven that a signature has existed.
	 */
	private Date bestSignatureTime;

	private static Date getLatestDate(Date firstDate, final Date secondDate) {

		if (firstDate != null && secondDate != null) {
			if (firstDate.before(secondDate)) {
				firstDate = secondDate;
			}
		} else if (secondDate != null) {
			firstDate = secondDate;
		}
		return firstDate;
	}

	private static Date getEarliestDate(Date firstDate, final Date secondDate) {

		if (firstDate != null && secondDate != null) {
			if (firstDate.after(secondDate)) {
				firstDate = secondDate;
			}
		} else if (secondDate != null) {
			firstDate = secondDate;
		}
		return firstDate;
	}

	/**
	 * Checks if each necessary data needed to carry out the validation process is present. The process can be called
	 * from different contexts. This method calls automatically the necessary sub processes to prepare all input data.
	 *
	 * @param mainXmlNode
	 */
	private void isInitialised(final XmlNode mainXmlNode) {

		assertDiagnosticData(context.getDiagnosticData(), getClass());
		assertValidationPolicy(context.getValidationPolicy(), getClass());
		Date currentTime = context.getCurrentTime();
		if (currentTime == null) {

			currentTime = new Date();
			if (LOG.isDebugEnabled()) {
				LOG.debug("Validation time set to: " + currentTime);
			}
			context.setCurrentTime(currentTime);
		}
		if (basicValidationXmlDom == null) {

			/**
			 * The execution of the Basic Validation process which creates the basic validation data.<br>
			 */
			final BasicValidation basicValidation = new BasicValidation();
			basicValidationXmlDom = basicValidation.run(mainXmlNode, context);
		}
		if (timestampValidationXmlDom == null) {

			/**
			 * This executes the Basic Building Blocks process for timestamps present in the signature.<br>
			 * This process needs the diagnostic and policy data. It creates the timestamps validation data.
			 */
			final TimestampValidation timeStampValidation = new TimestampValidation();
			timestampValidationXmlDom = timeStampValidation.run(mainXmlNode, context);
		}
	}

	/**
	 * This method runs the AdES-T validation process.
	 * <p/>
	 * 8.2 Inputs<br>
	 * - Signature ..................... Mandatory<br>
	 * - Signed data object (s) ........ Optional<br>
	 * - Trusted-status Service Lists .. Optional<br>
	 * - Signature Validation Policies . Optional<br>
	 * - Local configuration ........... Optional<br>
	 * - Signer's Certificate .......... Optional<br>
	 * <p/>
	 * 8.3 Outputs<BR>
	 * The main output of the signature validation is a status indicating the validity of the signature. This status may
	 * be accompanied by additional information (see clause 4).
	 * <p/>
	 * 8.4 Processing<BR>
	 * The following steps shall be performed:
	 *
	 * @param mainNode {@code XmlNode} container for the detailed report
	 * @param context  {@code ProcessParameters}
	 * @return {@code XmlDom} containing the part of the detailed report related to the current validation process
	 */
	public XmlDom run(final XmlNode mainNode, final ProcessParameters context) {

		this.context = context;
		isInitialised(mainNode);
		LOG.debug(this.getClass().getSimpleName() + ": start.");

		final XmlNode adestValidationDataXmlNode = mainNode.addChild(ADEST_VALIDATION_DATA);

		/**
		 * 1) Initialise the set of signature time-stamp tokens from the signature time-stamp properties/attributes
		 * present in the signature and initialise the best-signature-time to the current time.
		 *
		 * NOTE 1: Best-signature-time is an internal variable for the algorithm denoting the earliest time when it can be
		 * proven that a signature has existed.
		 */
		final List<XmlDom> signatureXmlDomList = context.getDiagnosticData().getElements(XP_DIAGNOSTIC_DATA_SIGNATURE);
		for (final XmlDom signatureXmlDom_ : signatureXmlDomList) {

			// Initialisation of local cache variables.
			signatureXmlDom = signatureXmlDom_;
			signatureId = signatureXmlDom.getAttribute(ID);
			final String signatureType = signatureXmlDom.getAttribute(TYPE);
			setSuitableValidationPolicy(context, signatureType);
			validationPolicy = context.getCurrentValidationPolicy();

			signatureXmlNode = adestValidationDataXmlNode.addChild(SIGNATURE);
			signatureXmlNode.setAttribute(ID, signatureId);

			// Teh best-signature-time is set to current-time.
			bestSignatureTime = context.getCurrentTime();

			final Conclusion conclusion = process();

			final XmlNode conclusionXmlNode = conclusion.toXmlNode();
			signatureXmlNode.addChild(conclusionXmlNode);
		}
		final XmlDom atvDom = adestValidationDataXmlNode.toXmlDom();
		context.setAdestXmlDom(atvDom);
		return atvDom;
	}

	/**
	 * 2)	Signature validation: Perform the validation process for BES signatures (see clause 6)
	 * with all the inputs, including the processing of any signed attributes/properties as specified.
	 * If this validation outputs:
	 * - VALID,
	 * - INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,
	 * - INDETERMINATE/REVOKED_NO_POE or
	 * - INDETERMINATE/OUT_OF_BOUNDS_NO_POE
	 * go to the next step. Otherwise, terminate with the returned status and information.
	 *
	 * @return the {@code Conclusion} which indicates the result of the process
	 */
	private Conclusion process() {

		final Conclusion signatureConclusion = new Conclusion();

		bvpConclusionXmlDom = basicValidationXmlDom.getElement(XP_BV_SIGNATURE_CONCLUSION, signatureId);
		bvpIndication = bvpConclusionXmlDom.getValue(XP_INDICATION);
		bvpSubIndication = bvpConclusionXmlDom.getValue(XP_SUB_INDICATION);

		if (!checkBasicValidationProcessConclusionConstraint(signatureConclusion)) {
			return signatureConclusion;
		}
		// The search of all timestamps to be analysed.
		final List<XmlDom> timestampXmlDomList = signatureXmlDom.getElements("./Timestamps/Timestamp");

		for (final XmlDom timestampXmlDom : timestampXmlDomList) {

			final String timestampId = timestampXmlDom.getAttribute(ID);
			final String timestampTypeString = timestampXmlDom.getAttribute(TYPE);
			final TimestampType timestampType = TimestampType.valueOf(timestampTypeString);
			final Date timestampProductionTime = timestampXmlDom.getTimeValue(XP_PRODUCTION_TIME);

			final XmlNode timestampXmlNode = signatureXmlNode.addChild(TIMESTAMP);
			timestampXmlNode.setAttribute(ID, timestampId);
			timestampXmlNode.setAttribute(TYPE, timestampTypeString);
			timestampXmlNode.setAttribute(AttributeName.PRODUCTION_TIME, DSSUtils.formatDate(timestampProductionTime));

			final Conclusion timestampConclusion = new Conclusion();

			if (checkMessageImprintDataFoundConstraint(timestampXmlNode, timestampConclusion, timestampId, timestampXmlDom)) {
				if (checkMessageImprintDataIntactConstraint(timestampXmlNode, timestampConclusion, timestampId, timestampXmlDom)) {
					checkSignatureTimestampValidationProcessConstraint(timestampXmlNode, timestampConclusion, timestampId, timestampType, timestampProductionTime);
				}
			}
			final XmlNode conclusionXmlNode = timestampConclusion.toXmlNode();
			timestampXmlNode.addChild(conclusionXmlNode);
		}

		if (!checkContentTimestampsNumberConstraint(signatureConclusion)) {
			return signatureConclusion;
		}

		if (!checkSignatureTimestampsNumberConstraint(signatureConclusion)) {
			return signatureConclusion;
		}

		if (!checkValidationDataTimestampNumberConstraint(signatureConclusion)) {
			return signatureConclusion;
		}

		if (!checkArchiveTimestampsNumberConstraint(signatureConclusion)) {
			return signatureConclusion;
		}

		/**
		 * 5) Comparing times:
		 */

		/**
		 * a) If step 2 returned INDETERMINATE/REVOKED_NO_POE: If the returned revocation time is posterior
		 * to best-signature-time, perform step 5d. Otherwise, terminate with INDETERMINATE/REVOKED_NO_POE.
		 */
		if (INDETERMINATE.equals(bvpIndication) && REVOKED_NO_POE.equals(bvpSubIndication)) {

			if (!checkRevocationTimeConstraint(signatureConclusion)) {
				signatureConclusion.addBasicInfo(bvpConclusionXmlDom);
				return signatureConclusion;
			}
		}

		/**
		 * b) If step 2 returned INDETERMINATE/OUT_OF_BOUNDS_NO_POE: If best-signature-time is before the
		 * issuance date of the signer's certificate, terminate with INVALID/NOT_YET_VALID. Otherwise,
		 * terminate with INDETERMINATE/OUT_OF_BOUNDS_NO_POE.
		 */
		if (INDETERMINATE.equals(bvpIndication) && OUT_OF_BOUNDS_NO_POE.equals(bvpSubIndication)) {

			if (!checkBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint(signatureConclusion)) {
				signatureConclusion.addBasicInfo(bvpConclusionXmlDom);
				return signatureConclusion;
			}
			if (!checkSigningCertificateValidityAtBestSignatureTimeConstraint(signatureConclusion)) {
				signatureConclusion.addBasicInfo(bvpConclusionXmlDom);
				return signatureConclusion;
			}
		}

		/**
		 * c) If step 2 returned INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material
		 * concerned by this failure is the signature value or a signed attribute, check, if the algorithm(s) concerned
		 * were still considered reliable at best-signature-time, continue with step d. Otherwise, terminate with
		 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
		 */
		if (INDETERMINATE.equals(bvpIndication) && CRYPTO_CONSTRAINTS_FAILURE_NO_POE.equals(bvpSubIndication)) {

			if (!checkAlgorithmReliableAtBestSignatureTimeConstraint(signatureConclusion)) {
				signatureConclusion.addBasicInfo(bvpConclusionXmlDom);
				return signatureConclusion;
			}
		}
		/**
		 * d) For each time-stamp token remaining in the set of signature time-stamp tokens, check the coherence in
		 * the values of the times indicated in the time-stamp tokens.
		 */
		if (!checkTimestampCoherenceConstraint(signatureConclusion)) {
			return signatureConclusion;
		}

		if (!checkSigningTimeProperty(signatureConclusion)) {
			return signatureConclusion;
		}

		if (!checkTimestampDelay(signatureConclusion)) {
			return signatureConclusion;
		}

		signatureConclusion.setIndication(VALID);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		signatureConclusion.addInfo(EMPTY).setAttribute(BEST_SIGNATURE_TIME, formatedBestSignatureTime);

		return signatureConclusion;
	}

	/**
	 * b) Time-stamp token validation: For each time-stamp token remaining in the set of signature time-stamp
	 * tokens, the SVA shall perform the time-stamp validation process (see clause 7):<br/>
	 * <p/>
	 * 􀀀 If VALID is returned and if the returned generation time is before best-signature-time, set
	 * best-signature-time to this date and try the next token.<br/>
	 * <p/>
	 * 􀀀 In all remaining cases, remove the time-stamp token from the set of signature time-stamp tokens and try
	 * the next token.<br/>
	 * --> -> This method is called in the context of a signature (signatureId) and a timestamp (timestampId)
	 *
	 * @param timestampXmlNode
	 * @param conclusion              the conclusion to use to add the result of the check
	 * @param timestampId
	 * @param timestampType
	 * @param timestampProductionTime the production {@code Date} of the current timestamp  @return
	 */
	private void checkSignatureTimestampValidationProcessConstraint(final XmlNode timestampXmlNode, final Conclusion conclusion, final String timestampId,
	                                                                final TimestampType timestampType, final Date timestampProductionTime) {

		final XmlDom tspvData = timestampValidationXmlDom.getElement(XP_TVD_SIGNATURE_TIMESTAMP, signatureId, timestampId);
		final XmlDom tsvpConclusion = tspvData.getElement(XP_BBB_CONCLUSION);
		final String tsvpIndication = tsvpConclusion.getValue(XP_INDICATION);

		final XmlNode constraintNode = addConstraint(timestampXmlNode, ADEST_ITVPC);

		boolean valid = VALID.equals(tsvpIndication);
		if (valid) {

			constraintNode.addChild(STATUS, OK);
			conclusion.setIndication(VALID);
			if (SIGNATURE_TIMESTAMP == timestampType) {

				if (timestampProductionTime.before(bestSignatureTime)) {

					bestSignatureTime = timestampProductionTime;
					constraintNode.addChild(INFO, ADEST_ITVPC_INFO_1).setAttribute(BEST_SIGNATURE_TIME, DSSUtils.formatDate(bestSignatureTime))
						  .setAttribute(TIMESTAMP_ID, timestampId);
				}
			}
			return;
		}
		constraintNode.addChild(STATUS, KO);
		conclusion.setIndication(tsvpIndication);
		final String tsvpSubIndication = tsvpConclusion.getValue(XP_SUB_INDICATION);
		conclusion.setSubIndication(tsvpSubIndication);
		conclusion.addError(ADEST_ITVPC_ANS_2).setAttribute(TIMESTAMP_ID, timestampId);
		conclusion.addBasicInfo(tsvpConclusion);
	}

	/**
	 * @param parent
	 * @param messageTag
	 * @return
	 */
	private XmlNode addConstraint(final XmlNode parent, final MessageTag messageTag) {

		XmlNode constraintNode = parent.addChild(CONSTRAINT);
		constraintNode.addChild(NAME, messageTag.getMessage()).setAttribute(NAME_ID, messageTag.name());
		return constraintNode;
	}

	/**
	 * Check of: the result of the basic validation process
	 * <p/>
	 * NOTE 2: We continue the process in the case INDETERMINATE/REVOKED_NO_POE, because a proof that the signing
	 * occurred before the revocation date may help to go from INDETERMINATE to VALID (step 5-a).
	 * <p/>
	 * NOTE 3: We continue the process in the case INDETERMINATE/OUT_OF_BOUNDS_NO_POE, because a proof that the
	 * signing occurred before the issuance date (notBefore) of the signer's certificate may help to go from
	 * INDETERMINATE to INVALID (step 5-b).
	 * <p/>
	 * NOTE 4: We continue the process in the case INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, because a proof
	 * that the signing occurred before the time one of the algorithms used was no longer considered secure may help
	 * to go from INDETERMINATE to VALID (step 5-c).
	 * <p/>
	 * AT: Problem of the revocation of the certificate after signing time --> Following the Austrian's laws the signature is still valid because the timestamps are not
	 * mandatory, what is an aberration. To obtain the validity of such a signature the rule which checks the revocation data should be set as WARN. Then here VALID
	 * indication is obtained.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkBasicValidationProcessConclusionConstraint(final Conclusion conclusion) {

		final BasicValidationProcessValidConstraint constraint = validationPolicy.getBasicValidationProcessConclusionConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, ADEST_ROBVPIIC);
		boolean validBasicValidationProcess = VALID.equals(bvpIndication) || INDETERMINATE.equals(bvpIndication) && (RuleUtils
			  .in(bvpSubIndication, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, OUT_OF_BOUNDS_NO_POE, REVOKED_NO_POE));
		constraint.setValue(validBasicValidationProcess);
		constraint.setBasicValidationProcessConclusionNode(bvpConclusionXmlDom);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: is the timestamp message imprint data found
	 * <p/>
	 * 4) Signature time-stamp validation: Perform the following steps:
	 * <p/>
	 * a) Message imprint verification: For each time-stamp token in the set of signature time-stamp tokens, do the
	 * message imprint verification as specified in clauses 8.4.1 or 8.4.2 depending on the type of the signature.
	 * If the verification fails, remove the token from the set.
	 *
	 * @param timestampXmlNode
	 * @param conclusion       the conclusion to use to add the result of the check
	 * @param timestampId
	 * @param timestampXmlDom  @return false if the check failed and the process should stop, true otherwise
	 */
	private boolean checkMessageImprintDataFoundConstraint(final XmlNode timestampXmlNode, final Conclusion conclusion, final String timestampId, final XmlDom timestampXmlDom) {

		final Constraint constraint = validationPolicy.getMessageImprintDataFoundConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(timestampXmlNode, ADEST_IMIDF);
		final boolean messageImprintDataIntact = timestampXmlDom.getBoolValue(XP_MESSAGE_IMPRINT_DATA_FOUND);
		constraint.setValue(messageImprintDataIntact);
		constraint.setIndications(INDETERMINATE, SIGNED_DATA_NOT_FOUND, ADEST_IMIDF_ANS);
		constraint.setAttribute(TIMESTAMP_ID, timestampId);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: is the timestamp message imprint data intact
	 *
	 * @param timestampXmlNode
	 * @param conclusion       the conclusion to use to add the result of the check
	 * @param timestampId
	 * @param timestampXmlDom  @return false if the check failed and the process should stop, true otherwise
	 */
	private boolean checkMessageImprintDataIntactConstraint(final XmlNode timestampXmlNode, final Conclusion conclusion, final String timestampId, final XmlDom timestampXmlDom) {

		final Constraint constraint = validationPolicy.getMessageImprintDataIntactConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(timestampXmlNode, ADEST_IMIVC);
		final boolean messageImprintDataIntact = timestampXmlDom.getBoolValue(XP_MESSAGE_IMPRINT_DATA_INTACT);
		constraint.setValue(messageImprintDataIntact);
		constraint.setIndications(INVALID, HASH_FAILURE, ADEST_IMIVC_ANS);
		constraint.setAttribute(TIMESTAMP_ID, timestampId);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: Is the result of the signature-timestamps validation process conclusive?
	 * -> This method is called in the context of a signature (signatureId) in the case of failure the individual timestamps must be retrieved (timestampId)
	 *
	 * @param conclusion the conclusion to use to add the result of the check
	 * @return false if the check failed and the process should stop, true otherwise
	 */
	private boolean checkSignatureTimestampsNumberConstraint(final Conclusion conclusion) {

		final ElementNumberConstraint constraint = validationPolicy.getSignatureTimestampNumberConstraint();
		if (constraint == null) {
			return true;
		}
		final String xPath = String.format(XP_TIMESTAMP_TYPE_CONCLUSION, SIGNATURE_TIMESTAMP);
		return prepareTimestampConstraint(conclusion, constraint, xPath, signatureXmlNode, BBB_SAV_DNSTCVP, BBB_SAV_DNSTCVP_ANS);
	}

	/**
	 * Check of: Is the result of the content-timestamps validation process conclusive?
	 * -> This method is called in the context of a signature (signatureId) in the case of failure the individual timestamps must be retrieved (timestampId)
	 *
	 * @param conclusion the conclusion to use to add the result of the check
	 * @return false if the check failed and the process should stop, true otherwise
	 */
	private boolean checkContentTimestampsNumberConstraint(final Conclusion conclusion) {

		final ElementNumberConstraint constraint = validationPolicy.getContentTimestampNumberConstraint();
		if (constraint == null) {
			return true;
		}
		int validContentTimestampNumber = 0;
		final Conclusion temporaryConclusion = new Conclusion();
		final XmlDom signatureXmlDom = signatureXmlNode.toXmlDom(XmlDom.NAMESPACE);
		final List<String> contentTimestampIdList = context.getContentTimestampIdList();
		for (final String contentTimestampId : contentTimestampIdList) {

			final List<XmlDom> signatureTimestampConclusionXmlDomList = signatureXmlDom.getElements(XP_TIMESTAMP_ID_CONCLUSION, contentTimestampId);
			for (final XmlDom signatureTimestampConclusionXmlDom : signatureTimestampConclusionXmlDomList) {

				final String signatureTimestampIndication = signatureTimestampConclusionXmlDom.getValue(XP_INDICATION);
				if (VALID.equals(signatureTimestampIndication)) {

					validContentTimestampNumber++;
				}
				temporaryConclusion.copyErrors(signatureTimestampConclusionXmlDom);
			}
		}
		constraint.setIntValue(validContentTimestampNumber);

		constraint.create(signatureXmlNode, BBB_SAV_DNCTCVP);
		constraint.setIndications(INVALID, SIG_CONSTRAINTS_FAILURE, BBB_SAV_DNCTCVP_ANS);
		final List<String> contentTimestampTypeList = validationPolicy.getContentTimestampTypeList();
		constraint.setAttribute("ExpectedTypeList", contentTimestampTypeList.toString());
		constraint.setConclusionReceiver(conclusion);

		final boolean check = constraint.check();
		if (!check) {
			conclusion.addBasicInfo(temporaryConclusion);
		}
		return check;
	}

	/**
	 * Check of: Is the result of the signature-timestamps validation process conclusive?
	 * -> This method is called in the context of a signature (signatureId) in the case of failure the individual timestamps must be retrieved (timestampId)
	 *
	 * @param conclusion the conclusion to use to add the result of the check
	 * @return false if the check failed and the process should stop, true otherwise
	 */
	private boolean checkArchiveTimestampsNumberConstraint(final Conclusion conclusion) {

		final ElementNumberConstraint constraint = validationPolicy.getArchiveTimestampNumberConstraint();
		if (constraint == null) {
			return true;
		}
		final String xPath = String.format(XP_TIMESTAMP_TYPE_CONCLUSION, ARCHIVE_TIMESTAMP);
		return prepareTimestampConstraint(conclusion, constraint, xPath, signatureXmlNode, BBB_SAV_2, BBB_SAV_2_ANS);
	}

	/**
	 * Check of: Is the result of the refs-only-timestamps validation process conclusive?
	 * -> This method is called in the context of a signature (signatureId) in the case of failure the individual timestamps must be retrieved (timestampId)
	 *
	 * @param conclusion the conclusion to use to add the result of the check
	 * @return false if the check failed and the process should stop, true otherwise
	 */
	private boolean checkValidationDataTimestampNumberConstraint(final Conclusion conclusion) {

		final ElementNumberConstraint constraint = validationPolicy.getValidationDataTimestampNumberConstraint();
		if (constraint == null) {
			return true;
		}
		final String xPath = String.format("./Timestamp[@Type='%s' or @Type='%s']/Conclusion", VALIDATION_DATA_REFSONLY_TIMESTAMP, VALIDATION_DATA_TIMESTAMP);
		return prepareTimestampConstraint(conclusion, constraint, xPath, signatureXmlNode, BBB_SAV_1, BBB_SAV_1_ANS);
	}

	private boolean prepareTimestampConstraint(final Conclusion conclusion, final ElementNumberConstraint constraint, final String xPath, final XmlNode signatureXmlNode,
	                                           final MessageTag question, final MessageTag answer) {

		int validTimestampNumber = 0;
		final Conclusion temporaryConclusion = new Conclusion();
		final XmlDom signatureXmlDom = signatureXmlNode.toXmlDom(XmlDom.NAMESPACE);
		final List<XmlDom> timestampConclusionXmlDomList = signatureXmlDom.getElements(xPath);
		for (final XmlDom timestampConclusionXmlDom : timestampConclusionXmlDomList) {

			final String timestampIndication = timestampConclusionXmlDom.getValue(XP_INDICATION);
			if (VALID.equals(timestampIndication)) {
				validTimestampNumber++;
			}
			temporaryConclusion.copyErrors(timestampConclusionXmlDom);
		}
		constraint.setIntValue(validTimestampNumber);

		constraint.create(signatureXmlNode, question);
		constraint.setIndications(INVALID, SIG_CONSTRAINTS_FAILURE, answer);
		constraint.setConclusionReceiver(conclusion);
		final boolean check = constraint.check();
		if (!check) {
			conclusion.addBasicInfo(temporaryConclusion);
		}
		return check;
	}

	/**
	 * Check of: Is revocation time posterior to best-signature-time?
	 * <p/>
	 * a) If step 2 returned INDETERMINATE/REVOKED_NO_POE: If the returned revocation time is posterior to
	 * best-signature-time, perform step 5d. Otherwise, terminate with INDETERMINATE/REVOKED_NO_POE. In addition to
	 * the data items returned in steps 1 and 2, the SVA should notify the DA with the reason of the failure.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkRevocationTimeConstraint(final Conclusion conclusion) {

		final Constraint constraint = validationPolicy.getRevocationTimeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, ADEST_IRTPTBST);
		constraint.setIndications(INDETERMINATE, REVOKED_NO_POE, ADEST_IRTPTBST_ANS);
		final Date revocationDate = bvpConclusionXmlDom.getTimeValue(XP_ERROR_REVOCATION_TIME);
		final boolean before = bestSignatureTime.before(revocationDate);
		constraint.setValue(before);
		final String certificateId = bvpConclusionXmlDom.getValue(XP_ERROR_CERTIFICATE_ID);
		constraint.setAttribute(CERTIFICATE_ID, certificateId);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: best-signature-time against the signing certificate issuance date.
	 * <p/>
	 * b) If step 2 returned INDETERMINATE/OUT_OF_BOUNDS_NO_POE: If best-signature-time is before the issuance date
	 * of the signer's certificate, terminate with INVALID/NOT_YET_VALID.
	 * <p/>
	 * NOTE 5: In the algorithm above, the signature-time-stamp protects the signature against the revocation of
	 * the signer's certificate (step 5-a) but not against expiration. The latter case requires validating the
	 * signer's certificate in the past (see clause 9).
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint(final Conclusion conclusion) {

		final Constraint constraint = validationPolicy.getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, TSV_IBSTAIDOSC);
		constraint.setIndications(INVALID, NOT_YET_VALID, TSV_IBSTAIDOSC_ANS);
		final String formatedNotBefore = bvpConclusionXmlDom.getValue(XP_ERROR_NOT_BEFORE);
		final Date notBeforeTime = DSSUtils.parseDate(formatedNotBefore);
		final boolean notBefore = !bestSignatureTime.before(notBeforeTime);
		constraint.setValue(notBefore);
		final String certificateId = bvpConclusionXmlDom.getValue(XP_ERROR_CERTIFICATE_ID);
		constraint.setAttribute(CERTIFICATE_ID, certificateId);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		constraint.setAttribute(NOT_BEFORE, formatedNotBefore);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: best-signature-time against the signing certificate issuance date.
	 * <p/>
	 * b) If step 2 returned INDETERMINATE/OUT_OF_BOUNDS_NO_POE: If best-signature-time is not before the issuance date
	 * of the signer's certificate terminate with INDETERMINATE/OUT_OF_BOUNDS_NO_POE. In addition to the data items returned
	 * in steps 1 and 2, the SVA should notify the DA with the reason of the failure.
	 * <p/>
	 * NOTE 5: In the algorithm above, the signature-time-stamp protects the signature against the revocation of
	 * the signer's certificate (step 5-a) but not against expiration. The latter case requires validating the
	 * signer's certificate in the past (see clause 9).
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSigningCertificateValidityAtBestSignatureTimeConstraint(final Conclusion conclusion) {

		final Constraint constraint = validationPolicy.getSigningCertificateValidityAtBestSignatureTimeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, TSV_ISCNVABST);
		constraint.setIndications(INDETERMINATE, OUT_OF_BOUNDS_NO_POE, TSV_ISCNVABST_ANS);
		constraint.setValue(false); // false is always returned: this corresponds to: Otherwise, terminate with INDETERMINATE/OUT_OF_BOUNDS_NO_POE.
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		final String certificateId = bvpConclusionXmlDom.getValue(XP_ERROR_CERTIFICATE_ID);
		constraint.setAttribute(CERTIFICATE_ID, certificateId);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: best-signature-time against the signing certificate issuance date.
	 * <p/>
	 * c) If step 2 returned INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE and the material concerned by this
	 * failure is the signature value or a signed attribute, check, if the algorithm(s) concerned were still
	 * considered reliable at best-signature-time, continue with step d. Otherwise, terminate with
	 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkAlgorithmReliableAtBestSignatureTimeConstraint(final Conclusion conclusion) {

		final Constraint constraint = validationPolicy.getAlgorithmReliableAtBestSignatureTimeConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, TSV_WACRABST);
		constraint.setIndications(INDETERMINATE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE, TSV_WACRABST_ANS);

		boolean ok = false;
		final XmlDom error = bvpConclusionXmlDom.getElement(XP_ERROR);
		if (error != null) {

			final String algorithmExpirationDateString = error.getAttribute("AlgorithmExpirationDate");
			if (DSSUtils.isNotBlank(algorithmExpirationDateString)) {

				final Date algorithmExpirationDate = DSSUtils.parseDate(DSSUtils.DEFAULT_DATE_FORMAT, algorithmExpirationDateString);
				if (!algorithmExpirationDate.before(bestSignatureTime)) {

					ok = true;
				}
			}
		}
		constraint.setValue(ok);
		final String formatedBestSignatureTime = DSSUtils.formatDate(bestSignatureTime);
		constraint.setAttribute(BEST_SIGNATURE_TIME, formatedBestSignatureTime);
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * d) For each time-stamp token remaining in the set of signature time-stamp tokens, check the coherence in the
	 * values of the times indicated in the time-stamp tokens. They shall be posterior to the times indicated in any
	 * time-stamp token computed on the signed data (i.e. any content-time-stamp signed attributes in CAdES or any
	 * AllDataObjectsTimeStamp or IndividualDataObjectsTimeStamp signed present properties in XAdES). The SVA shall
	 * apply the rules specified in RFC 3161 [11], clause 2.4.2 regarding the order of time-stamp tokens generated by
	 * the same or different TSAs given the accuracy and ordering fields' values of the TSTInfo field, unless stated
	 * differently by the Signature Constraints. If all the checks end successfully, go to the next step. Otherwise
	 * return INVALID/TIMESTAMP_ORDER_FAILURE.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkTimestampCoherenceConstraint(final Conclusion conclusion) {

		final Constraint constraint = validationPolicy.getTimestampCoherenceConstraint();
		if (constraint == null) {
			return true;
		}

		final XmlDom signatureXmlDom = signatureXmlNode.toXmlDom(XmlDom.NAMESPACE);
		final List<XmlDom> timestampXmlDomList = signatureXmlDom.getElements(XP_TIMESTAMP);
		final TimestampProductionDate timestamp = new TimestampProductionDate();
		for (final XmlDom timestampXmlDom : timestampXmlDomList) {

			final String timestampIndication = timestampXmlDom.getValue(XP_CONCLUSION_INDICATION);
			if (!VALID.equals(timestampIndication)) {
				continue;
			}
			final String timestampTypeString = timestampXmlDom.getAttribute(TYPE);
			final TimestampType timestampType = TimestampType.valueOf(timestampTypeString);
			final String productionTimeString = timestampXmlDom.getAttribute(AttributeName.PRODUCTION_TIME);
			final Date productionTime = DSSXMLUtils.getDate(productionTimeString);
			switch (timestampType) {
				case CONTENT_TIMESTAMP:
				case INDIVIDUAL_DATA_OBJECTS_TIMESTAMP:
				case ALL_DATA_OBJECTS_TIMESTAMP:
					if (timestamp.latestContentTime == null || timestamp.latestContentTime.before(productionTime)) {
						timestamp.latestContentTime = productionTime;
					}
					break;
				case SIGNATURE_TIMESTAMP:
					if (timestamp.latestSignatureTime == null || timestamp.latestSignatureTime.before(productionTime)) {
						timestamp.latestSignatureTime = productionTime;
					}
					if (timestamp.earliestSignatureTime == null || timestamp.earliestSignatureTime.after(productionTime)) {
						timestamp.earliestSignatureTime = productionTime;
					}
					break;
				case VALIDATION_DATA_REFSONLY_TIMESTAMP:
				case VALIDATION_DATA_TIMESTAMP:
					if (timestamp.latestValidationDataTime == null || timestamp.latestValidationDataTime.before(productionTime)) {
						timestamp.latestValidationDataTime = productionTime;
					}
					if (timestamp.earliestValidationDataTime == null || timestamp.earliestValidationDataTime.after(productionTime)) {
						timestamp.earliestValidationDataTime = productionTime;
					}
					break;
				case ARCHIVE_TIMESTAMP:
					if (timestamp.earliestArchiveTime == null || timestamp.earliestArchiveTime.after(productionTime)) {
						timestamp.earliestArchiveTime = productionTime;
					}
					break;
			}
		}

		if (timestamp.latestContentTime == null && timestamp.earliestSignatureTime == null && timestamp.earliestValidationDataTime == null && timestamp.earliestArchiveTime == null) {
			return true;
		}
		final String consistencyCheckResult = timestamp.checkConsistency();
		constraint.create(signatureXmlNode, TSV_ASTPTCT);
		constraint.setIndications(INVALID, TIMESTAMP_ORDER_FAILURE, TSV_ASTPTCT_ANS);
		constraint.setValue(consistencyCheckResult == null);
		if (consistencyCheckResult != null) {
			constraint.setAttribute("Inconsistency", consistencyCheckResult);
		}
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: Time-stamp delay.
	 * <p/>
	 * 6) Handling Time-stamp delay: If the validation constraints specify a time-stamp delay, do the following:
	 * <p/>
	 * a) If no signing-time property/attribute is present, fail with INDETERMINATE and an explanation that the
	 * validation failed due to the absence of claimed signing time.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkSigningTimeProperty(final Conclusion conclusion) {

		final Constraint constraint = validationPolicy.getTimestampDelaySigningTimePropertyConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, BBB_SAV_ISQPSTP);
		constraint.setIndications(INDETERMINATE, CLAIMED_SIGNING_TIME_ABSENT, ADEST_VFDTAOCST_ANS);
		final String signingTime = signatureXmlDom.getValue("./DateTime/text()");
		constraint.setValue(DSSUtils.isNotBlank(signingTime));
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	/**
	 * Check of: Time-stamp delay.
	 * <p/>
	 * b) If a signing-time property/attribute is present, check that the claimed time in the attribute plus the
	 * timestamp delay is after the best-signature-time. If the check is successful, go to the next step.
	 * Otherwise, fail with INVALID/SIG_CONSTRAINTS_FAILURE and an explanation that the validation failed due to
	 * the time-stamp delay constraint.
	 *
	 * @param conclusion the conclusion to use to add the result of the check.
	 * @return false if the check failed and the process should stop, true otherwise.
	 */
	private boolean checkTimestampDelay(final Conclusion conclusion) {

		final Constraint constraint = validationPolicy.getTimestampDelaySigningTimePropertyConstraint();
		if (constraint == null) {
			return true;
		}
		constraint.create(signatureXmlNode, ADEST_ISTPTDABST);
		constraint.setIndications(INVALID, SIG_CONSTRAINTS_FAILURE, ADEST_ISTPTDABST_ANS);
		final Long timestampDelay = validationPolicy.getTimestampDelayTime();
		final String signingTime = signatureXmlDom.getValue("./DateTime/text()");
		final Date date = DSSUtils.quietlyParseDate(signingTime);
		constraint.setValue((date.getTime() + timestampDelay) > bestSignatureTime.getTime());
		constraint.setConclusionReceiver(conclusion);

		return constraint.check();
	}

	protected class TimestampProductionDate {

		Date latestContentTime = null;
		Date earliestSignatureTime = null;
		Date latestSignatureTime = null;
		Date earliestValidationDataTime = null;
		Date latestValidationDataTime = null;
		Date earliestArchiveTime = null;

		public String checkConsistency() {

			String inconsistency = null;
			if (earliestSignatureTime == null && (earliestValidationDataTime != null || earliestArchiveTime != null)) {

				inconsistency = "'signature-timestamp' is mandatory when 'validation-data' or 'archive' timestamps are present!";
				return inconsistency;
			}
			// Check content-timestamp against-signature timestamp
			if (latestContentTime != null && earliestSignatureTime != null) {
				if (!latestContentTime.before(earliestSignatureTime)) {

					inconsistency = "'content-timestamp' production time is after 'signature-timestamp'!";
					return inconsistency;
				}
			}

			// Check signature-timestamp against validation-data and validation-data-refs-only timestamp
			if (latestSignatureTime != null && earliestValidationDataTime != null) {
				if (!latestSignatureTime.before(earliestValidationDataTime)) {

					inconsistency = "'signature-timestamp' production time is after 'validation-data-timestamp'!";
					return inconsistency;
				}
			}

			// Check archive-timestamp
			if (latestSignatureTime != null && earliestArchiveTime != null) {
				if (!earliestArchiveTime.after(latestSignatureTime)) {

					inconsistency = "'signature-timestamp' production time is after 'archive-timestamp'!";
					return inconsistency;
				}
			}
			if (latestValidationDataTime != null && earliestArchiveTime != null) {
				if (!earliestArchiveTime.after(latestValidationDataTime)) {

					inconsistency = "'validation-data-timestamp' production time is after 'archive-timestamp'!";
					return inconsistency;
				}
			}
			return inconsistency;
		}
	}
}
