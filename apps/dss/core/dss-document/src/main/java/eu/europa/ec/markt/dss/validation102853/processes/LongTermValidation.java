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

import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.policy.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.processes.ltv.PastSignatureValidation;
import eu.europa.ec.markt.dss.validation102853.processes.ltv.PastSignatureValidationConclusion;
import eu.europa.ec.markt.dss.validation102853.processes.subprocesses.EtsiPOEExtraction;
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

import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IMIVC;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.ADEST_IMIVC_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.LTV_ITAPOE;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.LTV_ITAPOE_ANS;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.PSV_IATVC;
import static eu.europa.ec.markt.dss.validation102853.rules.MessageTag.PSV_IPSVC;

/**
 * 9.3 Long Term Validation Process<br>
 * <p/>
 * 9.3.1 Description<br>
 * <p/>
 * An AdES-A (Archival Electronic Signature) is built on an XL signature (EXtended Long Electronic Signature). Several
 * unsigned attributes may be present in such signatures:<br>
 * <p/>
 * • Time-stamp(s) on the signature value (AdES-T).<br>
 * • Attributes with references of validation data (AdES-C).<br>
 * • Time-stamp(s) on the references of validation data (AdES-XT2).<br>
 * • Time-stamp(s) on the references of validation data, the signature value and the signature time stamp (AdES-XT1).<br>
 * • Attributes with the values of validation data (AdES-XL).<br>
 * • Archive time-stamp(s) on the whole signature except the last archive time-stamp (AdES-A).<br>
 * <p/>
 * The process described in this clause is able to validate any of the forms above but also any basic form (namely BES
 * and EPES).<br>
 * <p/>
 * The process handles the AdES signature as a succession of layers of signatures. Starting from the most external layer
 * (e.g. the last archive-time-stamp) to the most inner layer (the signature value to validate), the process performs
 * the basic signature validation algorithm (see clause 8 for the signature itself and clause 7 for the time-stamps). If
 * the basic validation outputs INDETERMINATE/REVOKED_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE or
 * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE, we perform the past certificate validation which will output a
 * control-time in the past. The layer is accepted as VALID, provided we have a proof of existence before this
 * control-time.<br>
 * <p/>
 * The process does not necessarily fail when an intermediate time-stamp gives the status INVALID or INDETERMINATE
 * unless some validation constraints force the process to do so. If the validity of the signature can be ascertained
 * despite some time-stamps which were ignored due to INVALID (or INDETERMINATE) status, the SVA shall report this
 * information to the DA. What the DA does with this information is out of the scope of the present document.
 *
 * @author bielecro
 */
public class LongTermValidation extends BasicValidationProcess implements Indication, SubIndication, NodeName, NodeValue, AttributeName, ExceptionMessage {

	private static final Logger LOG = LoggerFactory.getLogger(LongTermValidation.class);

	ProcessParameters params;

	// Primary inputs
	private XmlDom timestampValidationData; // Basic Building Blocks for timestamps

	private XmlDom adestValidationData;

	// returned data
	private XmlNode signatureXmlNode;

	// LTV conclusion
	private Conclusion conclusion;

	// This object represents the set of POEs.
	private EtsiPOEExtraction poe;

	private void isInitialised(final XmlNode mainNode) {

		if (adestValidationData == null) {

			/**
			 * The execution of the Basic Validation process which creates the basic validation data.<br>
			 */
			final AdESTValidation adestValidation = new AdESTValidation();
			adestValidationData = adestValidation.run(mainNode, params);

			// Basic Building Blocks for timestamps
			timestampValidationData = params.getTsData();
		}
		if (poe == null) {

			poe = new EtsiPOEExtraction();
			params.setPOE(poe);
		}
	}

	/**
	 * This method lunches the long term validation process.
	 * <p/>
	 * 9.3.2 Input<br>
	 * Signature ..................... Mandatory<br>
	 * Signed data object (s) ........ Optional<br>
	 * Trusted-status Service Lists .. Optional<br>
	 * Signature Validation Policies . Optional<br>
	 * Local configuration ........... Optional<br>
	 * A set of POEs ................. Optional<br>
	 * Signer's Certificate .......... Optional<br>
	 * <p/>
	 * 9.3.3 Output<br>
	 * The main output of this signature validation process is a status indicating the validity of the signature. This
	 * status may be accompanied by additional information (see clause 4).<br>
	 * <p/>
	 * 9.3.4 Processing<br>
	 * The following steps shall be performed:
	 *
	 * @param mainNode {@code XmlNode} container for the detailed report
	 * @param params   {@code ProcessParameters}
	 * @return {@code XmlDom} containing the part of the detailed report related to the current validation process
	 */
	public XmlDom run(final XmlNode mainNode, final ProcessParameters params) {

		this.params = params;
		assertDiagnosticData(params.getDiagnosticData(), getClass());
		assertValidationPolicy(params.getValidationPolicy(), getClass());

		final GeneralStructure generalStructure = new GeneralStructure();
		final Conclusion generalStructureConclusion = generalStructure.run(params);
		mainNode.addChild(generalStructureConclusion.getValidationData());

		isInitialised(mainNode);
		if (LOG.isDebugEnabled()) {
			LOG.debug(this.getClass().getSimpleName() + ": start.");
		}

		XmlNode longTermValidationData = mainNode.addChild(LONG_TERM_VALIDATION_DATA);

		final List<XmlDom> signatureXmlDomList = params.getDiagnosticData().getElements(XP_DIAGNOSTIC_DATA_SIGNATURE);

		for (final XmlDom signatureXmlDom : signatureXmlDomList) {

			final String signatureId = signatureXmlDom.getAttribute(ID);
			final String signatureType = signatureXmlDom.getAttribute(TYPE);
			setSuitableValidationPolicy(params, signatureType);
			final XmlDom signatureTimestampValidationData = timestampValidationData.getElement(XP_SIGNATURE, signatureId);
			final XmlDom adestSignatureValidationData = adestValidationData.getElement(XP_ADEST_SIGNATURE, signatureId);

			signatureXmlNode = longTermValidationData.addChild(SIGNATURE);
			signatureXmlNode.setAttribute(ID, signatureId);

			conclusion = new Conclusion();
			try {

				final boolean valid = process(params, signatureXmlDom, signatureTimestampValidationData, adestSignatureValidationData);
				if (valid) {

					conclusion.setIndication(VALID);
				}
			} catch (Exception e) {
				// TODO-Bob (12/10/2015):  should not happen
				LOG.warn("Unexpected exception: " + e.toString(), e);
			}
			XmlNode conclusionXmlNode = conclusion.toXmlNode();
			conclusionXmlNode.setParent(signatureXmlNode);
		}
		final XmlDom ltvDom = longTermValidationData.toXmlDom();
		params.setLtvData(ltvDom);
		return ltvDom;
	}

	/**
	 * 9.3.4 Processing<br>
	 * <p/>
	 * The following steps shall be performed:<br>
	 *
	 * @param params
	 * @param signature
	 * @param signatureTimestampValidationData
	 * @param adestSignatureValidationData
	 * @return
	 */
	private boolean process(final ProcessParameters params, final XmlDom signature, final XmlDom signatureTimestampValidationData, final XmlDom adestSignatureValidationData) {

		/**
		 * 1) POE initialisation: Add a POE for each object in the signature at the current time to the set of POEs.<br>
		 *
		 * NOTE 1: The set of POE in the input may have been initialised from external sources (e.g. provided from an
		 * external archiving system). These POEs will be used without additional processing.<br>
		 */
		// --> The POEs at the current time are not added

		/**
		 * 2) Basic signature validation: Perform the validation process for AdES-T signatures (see clause 8) with all the
		 * inputs, including the processing of any signed attributes/properties as specified.<br>
		 */

		// --> This is done in the prepareParameters(ProcessParameters params) method.

		final XmlDom adestSignatureConclusion = adestSignatureValidationData.getElement(XP_CONCLUSION);
		final String adestSignatureIndication = adestSignatureConclusion.getValue(XP_INDICATION);

		/**
		 * - If the validation outputs VALID<br>
		 * - - If there is no validation constraint mandating the validation of the LTV attributes/properties, go to step
		 * 9.<br>
		 * - - Otherwise, go to step 3.<br>
		 */

		final XmlNode constraintXmlNode = addConstraint(signatureXmlNode, PSV_IATVC);

		if (VALID.equals(adestSignatureIndication)) {

			// TODO-Bob (12/10/2015):  Validation of -A form should be added if constraint mandates it
			constraintXmlNode.addChild(STATUS, OK);
			conclusion.addBasicInfo(adestSignatureConclusion);
			return true;
		}

		/**
		 * - If the validation outputs one of the following:<br>
		 * -- INDETERMINATE/REVOKED_NO_POE,<br>
		 * -- INDETERMINATE/REVOKED_CA_NO_POE,<br>
		 * -- INDETERMINATE/OUT_OF_BOUNDS_NO_POE or<br>
		 * -- INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE,<br>
		 * go to the next step.<br>
		 *
		 * - In all other cases, fail with returned code and information.<br>
		 *
		 * NOTE 2: We go to the LTV part of the validation process in the cases INDETERMINATE/REVOKED_NO_POE,
		 * INDETERMINATE/REVOKED_CA_NO_POE, INDETERMINATE/OUT_OF_BOUNDS_NO_POE and INDETERMINATE/
		 * CRYPTO_CONSTRAINTS_FAILURE_NO_POE because additional proof of existences may help to go from INDETERMINATE to a
		 * determined status.<br>
		 *
		 * NOTE 3: Performing the LTV part of the algorithm even when the basic validation gives VALID may be useful in
		 * the case the SVA is controlled by an archiving service. In such cases, it may be necessary to ensure that any
		 * LTV attribute/property present in the signature is actually valid before making a decision about the archival
		 * of the signature.<br>
		 */
		final String adestSignatureSubIndication = adestSignatureConclusion.getValue(XP_SUB_INDICATION);

		final boolean finalStatus = INDETERMINATE.equals(adestSignatureIndication) && (RuleUtils
			  .in(adestSignatureSubIndication, REVOKED_NO_POE, REVOKED_CA_NO_POE, OUT_OF_BOUNDS_NO_POE, CRYPTO_CONSTRAINTS_FAILURE_NO_POE));
		if (!finalStatus) {

			conclusion.copyConclusionAndAddBasicInfo(adestSignatureConclusion);
			constraintXmlNode.addChild(STATUS, KO);
			return false;
		}

		/**
		 * 3) If there is at least one long-term-validation attribute with a poeValue, process them, starting from the
		 * last (the newest) one as follows: Perform the time-stamp validation process (see clause 7) for the time-stamp
		 * in the poeValue:<br>
		 * a) If VALID is returned and the cryptographic hash function used in the time-stamp
		 * (MessageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp: Perform the POE
		 * extraction process with the signature, the long-term-validation attribute, the set of POEs and the
		 * cryptographic constraints as inputs. Add the returned POEs to the set of POEs.<br>
		 * b) Otherwise, perform past signature validation process with the following inputs: the time-stamp in the
		 * poeValue, the status/sub-indication returned in step 3, the TSA's certificate, the X.509 validation parameters,
		 * certificate meta-data, chain constraints, cryptographic constraints and the set of POEs. If it returns VALID
		 * and the cryptographic hash function used in the time-stamp is considered reliable at the generation time of the
		 * time-stamp, perform the POE extraction process and add the returned POEs to the set of POEs. In all other
		 * cases:<br>
		 * 􀀀 If no specific constraints mandating the validity of the attribute are specified in the validation
		 * constraints, ignore the attribute and consider the next long-term-validation attribute.<br>
		 * 􀀀 Otherwise, fail with the returned indication/sub-indication and associated explanations<br>
		 */

		// TODO 20130702 by bielecro: This must be implemented with the new CAdES Baseline Profile.
		// This is the part of the new CAdES specification:
		// http://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.01.01_60/ts_101733v020101p.pdf

		/**
		 * 4) If there is at least one archive-time-stamp attribute, process them, starting from the last (the newest)
		 * one, as follows: perform the time-stamp validation process (see clause 7):
		 */
		final XmlNode archiveTimestampsNode = signatureXmlNode.addChild(ARCHIVE_TIMESTAMPS);
		final List<XmlDom> archiveTimestamps = signature.getElements(XP_TIMESTAMPS, TimestampType.ARCHIVE_TIMESTAMP);
		if (archiveTimestamps.size() > 0) {

			dealWithTimestamp(archiveTimestampsNode, signatureTimestampValidationData, archiveTimestamps);
		}

		/**
		 * 5) If there is at least one time-stamp attribute on the references, process them, starting from the last one
		 * (the newest), as follows: perform the time-stamp validation process (see clause 7):<br>
		 */

		final XmlNode refsOnlyTimestampsNode = signatureXmlNode.addChild(REFS_ONLY_TIMESTAMPS);
		final List<XmlDom> refsOnlyTimestamps = signature.getElements(XP_TIMESTAMPS, TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP);
		if (refsOnlyTimestamps.size() > 0) {

			dealWithTimestamp(refsOnlyTimestampsNode, signatureTimestampValidationData, refsOnlyTimestamps);
		}

		/**
		 * 6) If there is at least one time-stamp attribute on the references and the signature value, process them,
		 * starting from the last one, as follows: perform the time-stamp validation process (see clause 7):<br>
		 */

		final XmlNode sigAndRefsTimestampsNode = signatureXmlNode.addChild(SIG_AND_REFS_TIMESTAMPS);
		final List<XmlDom> sigAndRefsTimestamps = signature.getElements(XP_TIMESTAMPS, TimestampType.VALIDATION_DATA_TIMESTAMP);
		if (sigAndRefsTimestamps.size() > 0) {

			dealWithTimestamp(sigAndRefsTimestampsNode, signatureTimestampValidationData, sigAndRefsTimestamps);
		}
		/**
		 * 7) If there is at least one signature-time-stamp attribute, process them, in the order of their appearance
		 * starting from the last one, as follows: Perform the time-stamp validation process (see clause 7)<br>
		 */

		final XmlNode timestampsNode = signatureXmlNode.addChild(SIGNATURE_TIMESTAMPS);
		final List<XmlDom> timestamps = signature.getElements(XP_TIMESTAMPS, TimestampType.SIGNATURE_TIMESTAMP);
		if (timestamps.size() > 0) {

			dealWithTimestamp(timestampsNode, signatureTimestampValidationData, timestamps);
		}
		if (!poe.isThereAnyPOE()) {

			conclusion.copyConclusionAndAddBasicInfo(adestSignatureConclusion);
			constraintXmlNode.addChild(STATUS, KO);
			return false;
		}
		constraintXmlNode.addChild(STATUS, OK);

		/**
		 * 8) Past signature validation: perform the past signature validation process with the following inputs: the
		 * signature, the status indication/sub-indication returned in step 2, the signer's certificate, the x.509
		 * validation parameters, certificate meta-data, chain constraints, cryptographic constraints and the set of POEs.
		 */

		final PastSignatureValidation pastSignatureValidation = new PastSignatureValidation();

		final PastSignatureValidationConclusion psvConclusion = pastSignatureValidation.run(params, signature, adestSignatureConclusion, MAIN_SIGNATURE);

		signatureXmlNode.addChild(psvConclusion.getValidationData());
		/**
		 * If it returns VALID go to the next step. Otherwise, abort with the returned indication/sub-indication and
		 * associated explanations.<br>
		 */

		final XmlNode psvConstraintXmlNode = addConstraint(signatureXmlNode, PSV_IPSVC);

		if (!VALID.equals(psvConclusion.getIndication())) {

			psvConstraintXmlNode.addChild(STATUS, KO);
			conclusion.copyConclusion(psvConclusion);
			conclusion.addBasicInfo(adestSignatureConclusion);
			return false;
		}
		psvConstraintXmlNode.addChild(STATUS, OK);

		/**
		 * Data extraction: the SVA shall return the success indication VALID. In addition, the SVA should return
		 * additional information extracted from the signature and/or used by the intermediate steps. In particular, the
		 * SVA should return intermediate results such as the validation results of any time-stamp token or time-mark.
		 * What the DA does with this information is out of the scope of the present document.<br>
		 */
		return true;
	}

	/**
	 * @param parentXmlNode
	 * @param signatureTimestampValidationData
	 * @param timestampXmlDomList
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private void dealWithTimestamp(final XmlNode parentXmlNode, final XmlDom signatureTimestampValidationData, final List<XmlDom> timestampXmlDomList) throws DSSException {

		Collections.sort(timestampXmlDomList, new TimestampComparator());
		for (final XmlDom timestampXmlDom : timestampXmlDomList) {

			final String timestampId = timestampXmlDom.getAttribute(ID);
			final XmlNode timestampXmlNode = parentXmlNode.addChild(TIMESTAMP);
			timestampXmlNode.setAttribute(ID, timestampId);
			try {

				/**
				 * FROM ADES-T (ETSI error ?!)
				 * 4) Signature time-stamp validation: Perform the following steps:
				 *
				 * a) Message imprint verification: For each time-stamp token in the set of signature time-stamp tokens, do the
				 * message imprint verification as specified in clauses 8.4.1 or 8.4.2 depending on the type of the signature.
				 * If the verification fails, remove the token from the set.
				 */

				XmlNode constraintXmlNode = addConstraint(timestampXmlNode, ADEST_IMIVC);

				final boolean messageImprintDataIntact = timestampXmlDom.getBoolValue(XP_MESSAGE_IMPRINT_DATA_INTACT);
				if (!messageImprintDataIntact) {

					constraintXmlNode.addChild(STATUS, KO);
					conclusion.addInfo(ADEST_IMIVC_ANS).setAttribute(TIMESTAMP_ID, timestampId);
					continue;
				}
				constraintXmlNode.addChild(STATUS, OK);

				final XmlDom timestampConclusionXmlDom = signatureTimestampValidationData.getElement(XP_TIMESTAMP_BBB_CONCLUSION, timestampId);
				final String timestampIndication = timestampConclusionXmlDom.getValue(XP_INDICATION);

				/**
				 * a) If VALID is returned and the cryptographic hash function used in the time-stamp
				 * (MessageImprint.hashAlgorithm) is considered reliable at the generation time of the time-stamp: Perform
				 * the POE extraction process with:<br>
				 * - the signature,<br>
				 * - the archive-time-stamp,<br>
				 * - the set of POEs and<br>
				 * - the cryptographic constraints as inputs.<br>
				 * Add the returned POEs to the set of POEs.
				 */
				if (VALID.equals(timestampIndication)) {

					timestampXmlNode.addChild(POE_EXTRACTION, OK);
					extractPOEs(timestampXmlDom);
				} else {

					constraintXmlNode = addConstraint(timestampXmlNode, LTV_ITAPOE);
					if (!poe.isThereAnyPOE()) {

						constraintXmlNode.addChild(STATUS, KO);
						conclusion.addError(LTV_ITAPOE_ANS).setAttribute(TIMESTAMP_ID, timestampId);
						continue; // if there is no PEO then process next timestamp
					}
					constraintXmlNode.addChild(STATUS, OK);

					/**
					 * b) Otherwise, perform past signature validation process with the following inputs:<br>
					 * - the archive time-stamp,<br>
					 * - the status/sub-indication returned in step 4,<br>
					 * - the TSA's certificate,<br>
					 * - the X.509 validation parameters,<br>
					 * - certificate meta-data, <br>
					 * - chain constraints,<br>
					 * - cryptographic constraints and<br>
					 * - the set of POEs.
					 */

					final PastSignatureValidation psvp = new PastSignatureValidation();
					final PastSignatureValidationConclusion psvConclusion = psvp.run(params, timestampXmlDom, timestampConclusionXmlDom, TIMESTAMP);

					timestampXmlNode.addChild(psvConclusion.getValidationData());

					/**
					 * If it returns VALID and the cryptographic hash function used in the time-stamp is considered reliable
					 * at the generation time of the time-stamp, perform the POE extraction process and add the returned POEs
					 * to the set of POEs.
					 */
					if (VALID.equals(psvConclusion.getIndication())) {

						final boolean couldExtract = extractPOEs(timestampXmlDom);
						if (couldExtract) {
							continue;
						}
					}
					/**
					 * In all other cases:<br>
					 * 􀀀 If no specific constraints mandating the validity of the attribute are specified in the validation
					 * constraints, ignore the attribute and consider the next archive-time-stamp attribute.<br>
					 */
					/**
					 * --> Concerning DSS there is no specific constraints.
					 */
					/**
					 * 􀀀 Otherwise, fail with the returned indication/sub-indication and associated explanations.<br>
					 *
					 * NOTE 4: If the signature is PAdES, document time-stamps replace archive-time-stamp attributes and the
					 * process "Extraction from a PDF document time-stamp" replaces the process
					 * "Extraction from an archive-time-stamp".<br>
					 */
				}
			} catch (Exception e) {
				throw new DSSException("Error for timestamp: id: " + timestampId, e);
			}
		}
	}

	/**
	 * @param timestamp
	 * @return
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private boolean extractPOEs(final XmlDom timestamp) throws DSSException {

		final String digestAlgorithm = RuleUtils.canonicalizeDigestAlgo(timestamp.getValue(XP_SIGNED_DATA_DIGEST_ALGO));
		final Date algorithmExpirationDate = params.getCurrentValidationPolicy().getAlgorithmExpirationDate(digestAlgorithm);
		final Date timestampProductionTime = timestamp.getTimeValue(XP_PRODUCTION_TIME);
		if (algorithmExpirationDate == null || timestampProductionTime.before(algorithmExpirationDate)) {

			poe.addPOE(timestamp, params.getCertPool());
			return true;
		}
		return false;
	}

	/**
	 * This method adds the constraint
	 *
	 * @param parentNode
	 * @param messageTag
	 * @return
	 */
	private XmlNode addConstraint(final XmlNode parentNode, final MessageTag messageTag) {

		final XmlNode constraintNode = parentNode.addChild(CONSTRAINT);
		constraintNode.addChild(NAME, messageTag.getMessage()).setAttribute(NAME_ID, messageTag.name());
		return constraintNode;
	}
}
