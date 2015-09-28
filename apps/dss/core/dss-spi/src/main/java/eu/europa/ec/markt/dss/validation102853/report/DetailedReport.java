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

package eu.europa.ec.markt.dss.validation102853.report;

import java.util.ArrayList;
import java.util.List;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.MessageTag;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class represents the detailed report built during the validation process. It contains information on each executed constraint. It is composed among other of the
 * following building blocks:<br/>
 * - Identification of the Signer's Certificate (ISC)<br/>
 * - Validation Context Initialization (VCI)<br/>
 * - X.509 Certificate Validation (XCV)<br/>
 * - Cryptographic Verification (CV)<br/>
 * - Signature Acceptance Validation (SAV)<br/>
 * - Basic Validation Process<br/>
 * - Validation Process for Time-Stamps<br/>
 * - Validation Process for AdES-T<br/>
 * - Validation of LTV forms<br/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DetailedReport extends XmlDom {

	public DetailedReport(final Document document) {

		super(document);
	}

	/**
	 * Returns the validation INDICATION of the GeneralStructureData.
	 *
	 * @return related {@code String} indication
	 */
	public String getGeneralStructureDataIndication() {

		final String indication = getValue("/ValidationData/GeneralStructureData/Conclusion/Indication/text()");
		return indication;
	}

	/**
	 * Returns the validation SUB_INDICATION of the GeneralStructureData.
	 *
	 * @return related {@code String} sub-indication
	 */
	public String getGeneralStructureDataSubIndication() {

		final String indication = getValue("/ValidationData/GeneralStructureData/Conclusion/SubIndication/text()");
		return indication;
	}

	/**
	 * Returns the number of the signatures into the signed document. The XML element: '/ValidationData/BasicBuildingBlocks/Signature' is used to obtain this information.
	 *
	 * @return {@code int} number of the retrieved signatures
	 */
	public int getBasicBuildingBlocksSignaturesNumber() {

		final int signaturesNumber = (int) getCountValue("count(/ValidationData/BasicBuildingBlocks/Signature)");
		return signaturesNumber;
	}

	/**
	 * Returns the id of the signature. The signature is identified by its index: 1 for the first one.
	 *
	 * @param index (position/order) of the signature within the report
	 * @return {@code String} identifying the signature
	 */
	public String getBasicBuildingBlocksSignatureId(final int index) {

		final String signatureId = getValue("/ValidationData/BasicBuildingBlocks/Signature[%s]/@Id", index);
		return signatureId;
	}

	/**
	 * This method returns the {@code List} of the signature id based on the XML element: '/ValidationData/BasicBuildingBlocks/Signature' within the report.
	 *
	 * @return {@code List} of the signature id
	 */
	public List<String> getBasicBuildingBlocksSignatureId() {

		return getIdList("/ValidationData/BasicBuildingBlocks/Signature");
	}

	/**
	 * Returns the validation INDICATION of the basic building blocks for the given signature id.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return related {@code String} indication
	 */
	public String getBasicBuildingBlocksIndication(final String signatureId) {

		final String indication = getValue("/ValidationData/BasicBuildingBlocks/Signature[@Id='%s']/Conclusion/Indication/text()", signatureId);
		return indication;
	}

	/**
	 * Returns the validation SUB_INDICATION of the basic building blocks for the given signature id.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return related {@code String} sub-indication
	 */
	public String getBasicBuildingBlocksSubIndication(final String signatureId) {

		final String indication = getValue("/ValidationData/BasicBuildingBlocks/Signature[@Id='%s']/Conclusion/SubIndication/text()", signatureId);
		return indication;
	}

	/**
	 * This method returns the {@code List} of the signature id based on the XML element: '/ValidationData/TimestampValidationData/Signature' within the report.
	 *
	 * @return {@code List} of the signature id
	 */
	public List<String> getTimestampValidationSignatureId() {

		return getIdList("/ValidationData/TimestampValidationData/Signature");
	}

	/**
	 * This method returns the {@code List} of the timestamp id for the given {@code TimestampType} based on TimestampValidationData.
	 *
	 * @param signatureId   {@code String} id of the signature
	 * @param timestampType {@code TimestampType}
	 * @return {@code List} of timestamp id
	 */
	public List<String> getTimestampValidationTimestampId(final String signatureId, final TimestampType timestampType) {

		return getIdList("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Type='%s']", signatureId, timestampType.name());
	}

	/**
	 * Returns the validation INDICATION of the timestamp validation for the given signature id.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return related {@code String} indication
	 */
	public String getTimestampValidationIndication(final String signatureId, final String timestampId) {

		final String indication = getValue("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion/Indication/text()",
			  signatureId, timestampId);
		return indication;
	}

	/**
	 * Returns the validation SUB_INDICATION of the timestamp validation for the given signature id.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return related {@code String} sub-indication
	 */
	public String getTimestampValidationSubIndication(final String signatureId, final String timestampId) {

		final String indication = getValue("/ValidationData/TimestampValidationData/Signature[@Id='%s']/Timestamp[@Id='%s']/BasicBuildingBlocks/Conclusion/SubIndication/text()",
			  signatureId, timestampId);
		return indication;
	}

	/**
	 * This method returns the {@code List} of the signature id based on the XML element: '/ValidationData/LongTermValidationData/Signature' within the report.
	 *
	 * @return {@code List} of the signature id
	 */
	public List<String> getLongTermValidationSignatureId() {

		return getIdList("/ValidationData/LongTermValidationData/Signature");
	}

	/**
	 * Returns the validation INDICATION of the long term validation for the given signature id.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return related {@code String} indication
	 */
	public String getLongTermValidationIndication(final String signatureId) {

		final String indication = getValue("/ValidationData/LongTermValidationData/Signature[@Id='%s']/Conclusion/Indication/text()", signatureId);
		return indication;
	}

	/**
	 * Returns the validation SUB_INDICATION of the long term validation for the given signature id.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return related {@code String} sub-indication
	 */
	public String getLongTermValidationSubIndication(final String signatureId) {

		final String indication = getValue("/ValidationData/LongTermValidationData/Signature[@Id='%s']/Conclusion/SubIndication/text()", signatureId);
		return indication;
	}

	/**
	 * This method checks if the basic building blocks have VALID indication. The check is performed for all signatures.
	 *
	 * @return {@code true} if basic building blocks (for all signatures) have VALID indication, otherwise {@code false}
	 */
	public boolean areBasicBuildingBlocksValid() {

		final List<XmlDom> indications = getElements("/ValidationData/BasicBuildingBlocks/Signature/Conclusion/Indication");
		return areAllIndicationsValid(indications);
	}

	/**
	 * This method returns the indication related to the AdESTValidation of a given signature.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return found {@code String} indication
	 */
	public String getAdESTValidationIndication(final String signatureId) {

		final String indication = getValue("/ValidationData/AdESTValidationData/Signature[@Id='%s']/Conclusion/Indication/text()", signatureId);
		return indication;
	}

	/**
	 * This method returns the subIndication related to the AdESTValidation of a given signature.
	 *
	 * @param signatureId {@code String} id of the signature
	 * @return found {@code String} sub-indication
	 */
	public String getAdESTValidationSubIndication(final String signatureId) {

		final String subIndication = getValue("/ValidationData/AdESTValidationData/Signature[@Id='%s']/Conclusion/SubIndication/text()", signatureId);
		return subIndication;
	}

	/**
	 * This method checks if the long term validation has VALID indication. The check is performed for all signatures.
	 *
	 * @return {@code true} if long term validation (for all signatures) has VALID indication, otherwise {@code false}
	 */
	public boolean isLongTermValidationValid() {

		final List<XmlDom> indications = getElements("/ValidationData/LongTermValidationData/Signature/Conclusion/Indication");
		return areAllIndicationsValid(indications);
	}

	/**
	 * This method checks if the timestamp validation has VALID indication. The check is performed for all signatures.
	 *
	 * @return {@code true} if timestamp validation (for all signatures) has VALID indication, otherwise {@code false}
	 */
	public boolean isTimestampValidationValid() {

		final List<XmlDom> indications = getElements("/ValidationData/TimestampValidationData/Signature/Timestamp/BasicBuildingBlocks/Conclusion/Indication");
		return areAllIndicationsValid(indications);
	}

	/**
	 * This method checks the timestamp validation indication for all signatures is VALID.
	 *
	 * @return {@code true} if VALID indication for all signatures, {@code null} if there is no timestamp, {@code false} otherwise.
	 */
	public Boolean isTimestampValidationValidOrEmpty() {

		final List<XmlDom> indications = getElements("/ValidationData/TimestampValidationData/Signature/Timestamp/BasicBuildingBlocks/Conclusion/Indication");
		if (indications.size() == 0) {
			return null;
		}
		return areAllIndicationsValid(indications);
	}

	/**
	 * This method returns the notice related to the signature policy.
	 *
	 * @param signatureId {@code String} id of the signature for which the check is to be done
	 * @return {@code String} describing the policy notice
	 */
	public String getPolicyNotice(final String signatureId) {

		final String notice = getValue("/ValidationData/BasicBuildingBlocks/Signature[@Id='%s']/VCI/Constraint/Notice/text()", signatureId);
		return notice;
	}

	/**
	 * This method returns the status of the constraint with the given tag.
	 *
	 * @param tag the tag of the constraint to find.
	 * @return the status of the constraint
	 */
	public String getConstraintStatus(final MessageTag tag) {

		final String status = getValue("//Name[@NameId='%s']/../Status/text()", tag.name());
		return status;
	}

	/**
	 * This method returns the {@code List} of {@code String} id based on the given XPath query and set of optional parameters.
	 *
	 * @param xPath      XPath query
	 * @param parameters array of {@code String }parameters
	 * @return {@code List} of id
	 */
	private List<String> getIdList(final String xPath, final String... parameters) {

		final List<String> idList = new ArrayList<String>();

		final List<XmlDom> elements = getElements(xPath, parameters);
		for (final XmlDom element : elements) {

			final String id = element.getAttribute("Id");
			idList.add(id);
		}

		return idList;
	}

	/**
	 * This method checks if all indications contained within the {@code indications} are VALID.
	 *
	 * @param indications {@code List} of {@code XmlDom} containing the INDICATION
	 * @return {@code true} if all contained indications are equal to VALID, otherwise {@code false}
	 */
	private boolean areAllIndicationsValid(final List<XmlDom> indications) {

		boolean valid = indications.size() > 0;
		for (final XmlDom indicationDom : indications) {

			final String indication = indicationDom.getText();
			valid = valid && Indication.VALID.equals(indication);
		}
		return valid;
	}
}
