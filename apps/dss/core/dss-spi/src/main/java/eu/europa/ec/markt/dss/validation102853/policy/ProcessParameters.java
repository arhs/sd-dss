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

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.process.POEExtraction;
import eu.europa.ec.markt.dss.validation102853.report.Conclusion;
import eu.europa.ec.markt.dss.validation102853.report.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class stores the references to data exchanged and manipulated by different sub validation processes.
 *
 * @author bielecro
 */
public class ProcessParameters implements AttributeName, ExceptionMessage {

	/**
	 * This variable contains the diagnostic data which is used to carry out all validation processes. It is extracted
	 * from the signature(s) being validated. This data is independent of the form of source signature (PDF, XAdES,
	 * PAdES, ASiC).
	 */
	protected DiagnosticData diagnosticData;

	/**
	 * This is the policy data to be used by the validation process. This data are not mandatory but in this case the
	 * ValidationContextInitialisation sub process will fail.
	 */
	protected ValidationPolicy validationPolicy;
	/**
	 * This is the current validation policy (either signature or countersignature).
	 */
	protected ValidationPolicy currentValidationPolicy;
	/**
	 * This is the current time against which the validation process is carried out.
	 */
	protected Date currentTime;
	/**
	 * Represents the current main signature DOM element being validated. This element provides general information used
	 * in validation process like the list of used certificates.
	 */
	protected XmlDom signatureXmlDom;

	/**
	 * Related id
	 */
	protected String signatureId;

	/**
	 * Represents the current signature DOM element being validated:<br>
	 * in the case of main signature validation {@code contextElement} is the signature element being validated;<br>
	 * in case of Timestamp signature validation {@code contextElement} is the timestamp element being validated.
	 */
	protected XmlDom contextElement;

	/**
	 * Indicates the current validation element like: MainSignature, SigningCertificate...
	 */
	protected String contextName;
	/**
	 * This is the countersignature policy data to be used by the validation process. This data are not mandatory but in this case the
	 * ValidationContextInitialisation sub process will fail.
	 */
	private ValidationPolicy countersignatureValidationPolicy;
	/**
	 * This variable contains the Signing Certificate Id. It is initialised by
	 * IdentificationOfTheSignersCertificate sub process.
	 * This variable is different for each context.
	 */
	private String signingCertificateId;
	/**
	 * This variable contains the Signing Certificate Node from diagnostic data. It is initialised by
	 * IdentificationOfTheSignersCertificate sub process.
	 * This variable is different for each context.
	 */
	private XmlDom signingCertificateXmlDom;
	/**
	 * This {@code XmlDom} is returned by the Basic Building Blocks process (see BasicBuildingBlocks) and
	 * it depicts the validation detailed report.
	 */
	private XmlDom basicBuildingBlocksXmlDom;

	/**
	 * This {@code XmlDom} is returned by the Basic Validation process (see BasicValidation) and
	 * it depicts the validation detailed report.
	 */
	private XmlDom bvXmlDom;

	/**
	 * This {@code XmlDom} is returned by the Basic Timestamp Validation process (see TimestampValidation)
	 * and it depicts the validation detailed report.
	 */
	private XmlDom tsXmlDom;

	/**
	 * This {@code XmlDom} is returned by the AdEST Validation process (see AdESTValidation) and
	 * it depicts the validation detailed report.
	 */
	private XmlDom adestXmlDom;

	/**
	 * This {@code XmlDom} is returned by the Long Term Validation process (see LongTermValidation) and
	 * it depicts the validation detailed report.
	 */
	private XmlDom ltvXmlDom;

	private XmlDom certPool;

	private POEExtraction poe;

	private Conclusion generalStructureConclusion;

	private List<String> contentTimestampIdList;

	/**
	 * See {@link #diagnosticData}
	 *
	 * @return
	 */
	public XmlDom getDiagnosticData() {
		return diagnosticData;
	}

	/**
	 * See {@link #diagnosticData}
	 * This method sets the used certificate pool.
	 *
	 * @return
	 */
	public void setDiagnosticData(final DiagnosticData diagnosticData) {

		this.diagnosticData = diagnosticData;
		final XmlDom usedCertificates = diagnosticData.getElement("/DiagnosticData/UsedCertificates");
		setCertPool(usedCertificates);
	}

	/**
	 * See {@link #validationPolicy}
	 *
	 * @return
	 */
	public ValidationPolicy getValidationPolicy() {
		return validationPolicy;
	}

	/**
	 * See {@link #validationPolicy}
	 *
	 * @return
	 */
	public void setValidationPolicy(final ValidationPolicy validationPolicy) {
		this.validationPolicy = validationPolicy;
	}

	public ValidationPolicy getCountersignatureValidationPolicy() {
		return countersignatureValidationPolicy;
	}

	public void setCountersignatureValidationPolicy(final ValidationPolicy countersignatureValidationPolicy) {
		this.countersignatureValidationPolicy = countersignatureValidationPolicy;
	}

	/**
	 * See {@link #currentValidationPolicy}
	 *
	 * @return
	 */
	public ValidationPolicy getCurrentValidationPolicy() {
		return currentValidationPolicy;
	}

	/**
	 * See {@link #currentValidationPolicy}
	 *
	 * @return
	 */
	public void setCurrentValidationPolicy(final ValidationPolicy currentValidationPolicy) {
		this.currentValidationPolicy = currentValidationPolicy;
	}

	/**
	 * See {@link #signingCertificateId}
	 *
	 * @return
	 */
	public String getSigningCertificateId() {
		return signingCertificateId;
	}

	/**
	 * See {@link #signingCertificateId}
	 *
	 * @return
	 */
	public void setSigningCertificateId(final String signingCertificateId) {
		this.signingCertificateId = signingCertificateId;
	}

	/**
	 * See {@link #signingCertificateXmlDom}
	 *
	 * @return
	 */
	public XmlDom getSigningCertificate() {
		return signingCertificateXmlDom;
	}

	/**
	 * See {@link #signingCertificateXmlDom}
	 *
	 * @return
	 */
	public void setSigningCertificate(final XmlDom signingCertificate) {
		this.signingCertificateXmlDom = signingCertificate;
	}

	/**
	 * See {@link #basicBuildingBlocksXmlDom}
	 *
	 * @return
	 */
	public XmlDom getBasicBuildingBlocksReport() {
		return basicBuildingBlocksXmlDom;
	}

	/**
	 * See {@link #basicBuildingBlocksXmlDom}
	 *
	 * @return
	 */
	public void setBasicBuildingBlocksReport(final XmlDom basicBuildingBlocksReport) {
		this.basicBuildingBlocksXmlDom = basicBuildingBlocksReport;
	}

	/**
	 * See {@link #bvXmlDom}
	 *
	 * @return
	 */
	public XmlDom getBvXmlDom() {
		return bvXmlDom;
	}

	/**
	 * See {@link #bvXmlDom}
	 *
	 * @return
	 */
	public void setBvXmlDom(XmlDom bvXmlDom) {
		this.bvXmlDom = bvXmlDom;
	}

	/**
	 * See {@link #tsXmlDom}
	 *
	 * @return
	 */
	public XmlDom getTsXmlDom() {
		return tsXmlDom;
	}

	/**
	 * See {@link #tsXmlDom}
	 *
	 * @return
	 */
	public void setTsXmlDom(XmlDom tsXmlDom) {
		this.tsXmlDom = tsXmlDom;
	}

	/**
	 * See {@link #adestXmlDom}
	 *
	 * @return
	 */

	public XmlDom getAdestXmlDom() {
		return adestXmlDom;
	}

	/**
	 * See {@link #adestXmlDom}
	 *
	 * @return
	 */
	public void setAdestXmlDom(XmlDom adestXmlDom) {
		this.adestXmlDom = adestXmlDom;
	}

	/**
	 * See {@link #ltvXmlDom}
	 *
	 * @return
	 */

	public XmlDom getLtvXmlDom() {
		return ltvXmlDom;
	}

	/**
	 * See {@link #ltvXmlDom}
	 *
	 * @return
	 */
	public void setLtvXmlDom(XmlDom ltvXmlDom) {
		this.ltvXmlDom = ltvXmlDom;
	}

	/**
	 * See {@link #currentTime}
	 *
	 * @return
	 */
	public Date getCurrentTime() {
		return currentTime;
	}

	/**
	 * See {@link #currentTime}
	 *
	 * @return
	 */
	public void setCurrentTime(final Date currentTime) {
		if (this.currentTime != null) {

			throw new DSSException(EXCEPTION_CTVSBIOO);
		}
		this.currentTime = currentTime;
	}

	/**
	 * See {@link #signatureXmlDom}
	 *
	 * @return
	 */
	public XmlDom getSignatureContext() {
		return signatureXmlDom;
	}

	/**
	 * See {@link #signatureXmlDom}
	 * This method sets local variable {@code signatureId}
	 *
	 * @param signature
	 */
	public void setSignatureContext(final XmlDom signature) {
		this.signatureXmlDom = signature;
		signatureId = signatureXmlDom.getAttribute(ID);
	}

	/**
	 * @return
	 */
	public String getSignatureId() {
		return signatureId;
	}

	/**
	 * See {@link #contextElement}
	 *
	 * @return
	 */
	public XmlDom getContextElement() {
		return contextElement;
	}

	/**
	 * See {@link #contextElement}
	 *
	 * @param contextElement
	 */
	public void setContextElement(final XmlDom contextElement) {
		this.contextElement = contextElement;
	}

	/**
	 * See {@link #contextElement}
	 *
	 * @return
	 */
	public String getContextName() {
		return contextName;
	}

	/**
	 * See {@link #contextElement}
	 *
	 * @param contextElement
	 */
	public void setContextName(final String contextElement) {
		this.contextName = contextElement;
	}

	/**
	 * @return the {@code XmlDom} object representing the pool of the certificates used in the validation process.
	 */
	public XmlDom getCertPool() {
		return certPool;
	}

	public void setCertPool(final XmlDom certPool) {
		this.certPool = certPool;
	}

	/**
	 * @param id the {@code int} SD-DSS certificate unique identifier
	 * @return the {@code XmlDom} representing the corresponding certificate or null.
	 */

	public XmlDom getCertificate(int id) {

		return getCertificate(String.valueOf(id));
	}

	/**
	 * @param id the {@code String} SD-DSS certificate unique identifier
	 * @return Returns the {@code XmlDom} representing the corresponding certificate or null.
	 */

	public XmlDom getCertificate(final String id) {

		return certPool == null ? certPool : certPool.getElement("./Certificate[@Id='%s']", id);
	}

	public POEExtraction getPOE() {
		return poe;
	}

	public void setPOE(final POEExtraction poe) {
		this.poe = poe;
	}

	public Conclusion getGeneralStructureConclusion() {
		return generalStructureConclusion;
	}

	public void setGeneralStructureConclusion(final Conclusion generalStructureConclusion) {
		this.generalStructureConclusion = generalStructureConclusion;
	}

	@Override
	public String toString() {

		try {

			StringBuilder builder = new StringBuilder();
			builder.append("currentTime: ").append(currentTime).append("\n");
			builder.append("signingCertificateId: ").append(signingCertificateId).append("\n");
			builder.append("contextName: ").append(contextName).append("\n");

			return builder.toString();
		} catch (Exception e) {

			return super.toString();
		}
	}

	/**
	 * @return the {@code List} of content-timestamp-id obtained in SAV building block
	 */
	public List<String> getContentTimestampIdList() {
		return contentTimestampIdList;
	}

	/**
	 * @param contentTimestampIdList sets the {@code List} of content-timestamp-id obtained in SAV building block
	 */
	public void setContentTimestampIdList(final List<String> contentTimestampIdList) {

		this.contentTimestampIdList = contentTimestampIdList;
	}
}