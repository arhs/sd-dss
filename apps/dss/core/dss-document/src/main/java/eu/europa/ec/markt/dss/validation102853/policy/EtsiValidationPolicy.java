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

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class encapsulates the constraint file that controls the policy to be used during the validation process. It
 * adds the functions to direct access to the file data. It is the implementation of the ETSI 102853 standard.
 *
 * @author bielecro
 */
public class EtsiValidationPolicy extends ValidationPolicy implements AttributeName, AttributeValue {

	protected static final String XP_ROOT = "/ConstraintsParameters";

	private long maxRevocationFreshnessString;

	private String maxRevocationFreshnessUnit;

	private Long maxRevocationFreshness;

	private Long timestampDelayTime;
	private Map<String, Date> algorithmExpirationDate = new HashMap<String, Date>();

	public EtsiValidationPolicy(Document document) {

		super(document);
	}

	@Override
	public boolean isRevocationFreshnessToBeChecked() {

		return null != getElement(XP_ROOT + "/Revocation/RevocationFreshness/");
	}

	@Override
	public String getFormatedMaxRevocationFreshness() {

		if (maxRevocationFreshness == null) {

			getMaxRevocationFreshness();
		}
		return maxRevocationFreshnessString + " " + maxRevocationFreshnessUnit;
	}

	@Override
	public Long getMaxRevocationFreshness() {

		if (maxRevocationFreshness == null) {

			maxRevocationFreshness = Long.MAX_VALUE;

			final XmlDom revocationFreshness = getElement(XP_ROOT + "/Revocation/RevocationFreshness");
			if (revocationFreshness != null) {

				maxRevocationFreshnessString = getLongValue(XP_ROOT + "/Revocation/RevocationFreshness/text()");
				maxRevocationFreshnessUnit = getValue(XP_ROOT + "/Revocation/RevocationFreshness/@Unit");
				maxRevocationFreshness = RuleUtils.convertDuration(maxRevocationFreshnessUnit, "MILLISECONDS", maxRevocationFreshnessString);
				if (maxRevocationFreshness == 0) {

					maxRevocationFreshness = Long.MAX_VALUE;
				}
			}
		}
		return maxRevocationFreshness;
	}

	@Override
	public Date getAlgorithmExpirationDate(final String algorithm) {

		Date date = algorithmExpirationDate.get(algorithm);
		if (date == null) {

			final XmlDom algoExpirationDateDom = getElement(XP_ROOT + "/Timestamp/Cryptographic/AlgoExpirationDate");
			if (algoExpirationDateDom == null) {

				return null;
			}
			String expirationDateFormat = algoExpirationDateDom.getValue("./@Format");
			if (expirationDateFormat.isEmpty()) {

				expirationDateFormat = "yyyy-MM-dd";
			}

			final String expirationDateString = algoExpirationDateDom.getValue("./Algo[@Name='%s']/text()", algorithm);
			if (expirationDateString.isEmpty()) {

				throw new DSSException(String.format("The the expiration date is not defined for '%s' algorithm!", algorithm));
			}
			date = DSSUtils.parseDate(expirationDateFormat, expirationDateString);
			algorithmExpirationDate.put(algorithm, date);
		}
		return date;
	}

	@Override
	public SignaturePolicyConstraint getSignaturePolicyConstraint() {

		final String level = getValue(XP_ROOT + "/MainSignature/AcceptablePolicies/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final SignaturePolicyConstraint constraint = new SignaturePolicyConstraint(level);

			final List<XmlDom> policyList = getElements(XP_ROOT + "/MainSignature/AcceptablePolicies/Id");
			final List<String> identifierList = XmlDom.convertToStringList(policyList);
			constraint.setIdentifiers(identifierList);
			constraint.setExpectedValue(identifierList.toString());
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getSignatureFormatConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/AcceptableSignatureFormats";
		final String level = getValue(xpRoot + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> signatureFormats = getElements(xpRoot + "/Format");
			final List<String> signatureFormatList = XmlDom.convertToStringList(signatureFormats);
			constraint.setExpectedValue(signatureFormatList.toString());
			constraint.setIdentifiers(signatureFormatList);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getStructuralValidationConstraint() {

		final String xpRoot = "/MainSignature/StructuralValidation";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getDataObjectFormatConstraint() {

		final String xpRoot = "/MainSignature/MandatedSignedQProperties/DataObjectFormat";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningTimeConstraint() {

		final String xpRoot = "/MainSignature/MandatedSignedQProperties/SigningTime";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getContentTypeConstraint() {

		final String xpRoot = "/MainSignature/MandatedSignedQProperties/ContentType";
		return getBasicConstraint(xpRoot, true);
	}


	@Override
	public Constraint getContentHintsConstraint() {

		final String xpRoot = "/MainSignature/MandatedSignedQProperties/ContentHints";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getContentIdentifierConstraint() {

		final String xpRoot = "/MainSignature/MandatedSignedQProperties/ContentIdentifier";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getCommitmentTypeIndicationConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedSignedQProperties/CommitmentTypeIndication";
		final String level = getValue(xpRoot + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> commitmentTypeIndications = getElements(xpRoot + "/Identifier");
			final List<String> identifierList = XmlDom.convertToStringList(commitmentTypeIndications);
			constraint.setExpectedValue(identifierList.toString());
			constraint.setIdentifiers(identifierList);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getSignerLocationConstraint() {

		final String level = getValue(XP_ROOT + "/MainSignature/MandatedSignedQProperties/SignerLocation/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			return constraint;
		}
		return null;
	}

	@Override
	public ElementNumberConstraint getContentTimestampNumberConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedSignedQProperties/ContentTimestamp";
		final ElementNumberConstraint elementNumberConstraint = getElementNumberConstraint(xpRoot);
		if (elementNumberConstraint != null) {
			return elementNumberConstraint;
		}
		return null;
	}

	@Override
	public List<String> getContentTimestampTypeList() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedSignedQProperties/ContentTimestamp/Type";
		final List<XmlDom> elementXmlList = getElements(xpRoot);
		List<String> foundTypeList = new ArrayList<String>();
		for (final XmlDom elementXmlDom : elementXmlList) {
			foundTypeList.add(elementXmlDom.getText());
		}
		return foundTypeList;
	}

	@Override
	public Constraint getClaimedRoleConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedSignedQProperties/ClaimedRoles";
		final String level = getValue(xpRoot + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> claimedRoles = getElements(xpRoot + "/Role");
			final List<String> claimedRoleList = XmlDom.convertToStringList(claimedRoles);
			constraint.setExpectedValue(claimedRoleList.toString());
			constraint.setIdentifiers(claimedRoleList);
			return constraint;
		}
		return null;
	}

	@Override
	public List<String> getClaimedRoles() {

		final List<XmlDom> list = getElements(XP_ROOT + "/MainSignature/MandatedSignedQProperties/ClaimedRoles/Role");
		final List<String> claimedRoles = XmlDom.convertToStringList(list);
		return claimedRoles;
	}

	@Override
	public Constraint getCertifiedRoleConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedSignedQProperties/CertifiedRoles";
		final String level = getValue(xpRoot + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> certifiedRoleXmlDomList = getElements(xpRoot + "/Role");
			final List<String> certifiedRoleList = XmlDom.convertToStringList(certifiedRoleXmlDomList);

			constraint.setExpectedValue(certifiedRoleList.toString());
			constraint.setIdentifiers(certifiedRoleList);
			return constraint;
		}
		return null;
	}


	@Override
	public String getPolicyName() {

		final String policy = getValue(XP_ROOT + "/@Name");
		return policy;
	}

	@Override
	public String getPolicyDescription() {

		final String description = getValue(XP_ROOT + "/Description/text()");
		return description;
	}

	@Override
	public Long getTimestampDelayTime() {

		if (timestampDelayTime == null) {

			final XmlDom timestampDelayPresent = getElement(XP_ROOT + "/Timestamp/TimestampDelay");
			if (timestampDelayPresent == null) {
				return null;
			}
			final long timestampDelay = getLongValue(XP_ROOT + "/Timestamp/TimestampDelay/text()");
			final String timestampUnit = getValue(XP_ROOT + "/Timestamp/TimestampDelay/@Unit");
			timestampDelayTime = RuleUtils.convertDuration(timestampUnit, "MILLISECONDS", timestampDelay);
		}
		return timestampDelayTime;
	}

	@Override
	public String getClaimedRolesAttendance() {

		String attendance = getValue("ConstraintsParameters/MainSignature/MandatedSignedQProperties/ClaimedRoles/@Attendance");
		return attendance;
	}

	@Override
	public SignatureCryptographicConstraint getSignatureCryptographicConstraint(final String context) {

		final String rootXPathQuery = String.format(XP_ROOT + "/%s/Cryptographic", context);
		return getSignatureCryptographicConstraint_(rootXPathQuery, context, null);
	}

	@Override
	public SignatureCryptographicConstraint getSignatureCryptographicConstraint(final String context, final String subContext) {

		final String rootXPathQuery = String.format(XP_ROOT + "/%s/%s/Cryptographic", context, subContext);
		return getSignatureCryptographicConstraint_(rootXPathQuery, context, subContext);
	}

	@Override
	protected SignatureCryptographicConstraint getSignatureCryptographicConstraint_(final String rootXPathQuery, final String context, final String subContext) {

		final String level = getValue(rootXPathQuery + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final SignatureCryptographicConstraint constraint = new SignatureCryptographicConstraint(level, context, subContext);

			final List<XmlDom> encryptionAlgoList = getElements(rootXPathQuery + "/AcceptableEncryptionAlgo/Algo");
			final List<String> encryptionAlgoStringList = XmlDom.convertToStringList(encryptionAlgoList);
			constraint.setEncryptionAlgorithms(encryptionAlgoStringList);

			final List<XmlDom> digestAlgoList = getElements(rootXPathQuery + "/AcceptableDigestAlgo/Algo");
			final List<String> digestAlgoStringList = XmlDom.convertToStringList(digestAlgoList);
			constraint.setDigestAlgorithms(digestAlgoStringList);

			final List<XmlDom> miniPublicKeySizeList = getElements(rootXPathQuery + "/MiniPublicKeySize/Algo");
			final Map<String, String> miniPublicKeySizeStringMap = XmlDom.convertToStringMap(miniPublicKeySizeList, SIZE);
			constraint.setMinimumPublicKeySizes(miniPublicKeySizeStringMap);

			final List<XmlDom> algoExpirationDateList = getElements(XP_ROOT + "/Cryptographic/AlgoExpirationDate/Algo");
			final Map<String, Date> algoExpirationDateStringMap = XmlDom.convertToStringDateMap(algoExpirationDateList, DATE);
			constraint.setAlgorithmExpirationDates(algoExpirationDateStringMap);

			return constraint;
		}
		return null;
	}

	@Override
	public ManifestCryptographicConstraint getManifestCryptographicConstraint() {

		final String rootXPathQuery = XP_ROOT + "/MainSignature/Manifest/Cryptographic";
		final String level = getValue(rootXPathQuery + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final ManifestCryptographicConstraint constraint = new ManifestCryptographicConstraint(level);

			final List<XmlDom> digestAlgoList = getElements(rootXPathQuery + "/AcceptableDigestAlgo/Algo");
			final List<String> digestAlgoStringList = XmlDom.convertToStringList(digestAlgoList);
			constraint.setDigestAlgorithms(digestAlgoStringList);

			final List<XmlDom> algoExpirationDateList = getElements(XP_ROOT + "/Cryptographic/AlgoExpirationDate/Algo");
			final Map<String, Date> algoExpirationDateStringMap = XmlDom.convertToStringDateMap(algoExpirationDateList, DATE);
			constraint.setAlgorithmExpirationDates(algoExpirationDateStringMap);

			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getSigningCertificateKeyUsageConstraint(final String context) {

		final String level = getValue(XP_ROOT + "/%s/SigningCertificate/KeyUsage/@Level", context);
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			final List<XmlDom> keyUsages = getElements(XP_ROOT + "/%s/SigningCertificate/KeyUsage/Identifier", context);
			final List<String> identifierList = XmlDom.convertToStringList(keyUsages);
			constraint.setExpectedValue(identifierList.toString());
			constraint.setIdentifiers(identifierList);
			return constraint;
		}
		return null;
	}

	@Override
	public CertificateExpirationConstraint getSigningCertificateExpirationConstraint(final String context, final String subContext) {

		final String level = getValue(String.format(XP_ROOT + "/%s/%s/Expiration/@Level", context, subContext));
		if (DSSUtils.isNotBlank(level)) {

			final CertificateExpirationConstraint constraint = new CertificateExpirationConstraint(level);
			return constraint;
		}
		return null;
	}

	@Override
	public Constraint getProspectiveCertificateChainConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/ProspectiveCertificateChain", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getCertificateSignatureConstraint(final String context, final String subContext) {

		final String xpRoot = String.format("/%s/%s/Signature", context, subContext);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getRevocationDataAvailableConstraint(final String context, final String subContext) {

		final String xpRoot = String.format("/%s/%s/RevocationDataAvailable", context, subContext);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getRevocationDataIsTrustedConstraint(final String context, final String subContext) {

		final String xpRoot = String.format("/%s/%s/RevocationDataIsTrusted", context, subContext);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getRevocationDataFreshnessConstraint(final String context, final String subContext) {

		final String xpRoot = String.format("/%s/%s/RevocationDataFreshness", context, subContext);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateRevokedConstraint(final String context, final String subContext) {

		final String xpRoot = String.format("/%s/%s/Revoked", context, subContext);
		return getBasicConstraint(xpRoot, false);
	}

	@Override
	public Constraint getSigningCertificateOnHoldConstraint(final String context, final String subContext) {

		final String xpRoot = String.format("/%s/%s/OnHold", context, subContext);
		return getBasicConstraint(xpRoot, false);
	}

	@Override
	public Constraint getSigningCertificateTSLValidityConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/TSLValidity", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateTSLStatusConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/TSLStatus", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateTSLStatusAndValidityConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/TSLStatusAndValidity", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getIntermediateCertificateRevokedConstraint(final String context) {

		final String xpRoot = String.format("/%s/CACertificate/Revoked", context);
		return getBasicConstraint(xpRoot, false);
	}

	@Override
	public Constraint getChainConstraint() {

		final String xpRoot = "/MainSignature/CertificateChain";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateQualificationConstraint() {

		final String xpRoot = "/MainSignature/SigningCertificate/Qualification";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateSupportedBySSCDConstraint() {

		final String xpRoot = "/MainSignature/SigningCertificate/SupportedBySSCD";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateIssuedToLegalPersonConstraint() {

		final String xpRoot = "/MainSignature/SigningCertificate/IssuedToLegalPerson";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateRecognitionConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/Recognition", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateSignedConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/Signed", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateAttributePresentConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/AttributePresent", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateDigestValuePresentConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/DigestValuePresent", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateDigestValueMatchConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/DigestValueMatch", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateIssuerSerialMatchConstraint(final String context) {

		final String xpRoot = String.format("/%s/SigningCertificate/IssuerSerialMatch", context);
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getReferenceDataExistenceConstraint() {

		final String xpRoot = "/MainSignature/ReferenceDataExistence";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getReferenceDataIntactConstraint() {

		final String xpRoot = "/MainSignature/ReferenceDataIntact";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSignatureIntactConstraint() {

		final String xpRoot = "/MainSignature/SignatureIntact";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	protected Constraint getBasicConstraint(final String xpRoot, final boolean defaultExpectedValue) {

		final String level = getValue(XP_ROOT + xpRoot + "/@Level");
		if (DSSUtils.isNotBlank(level)) {

			final Constraint constraint = new Constraint(level);
			String expectedValue = getValue(XP_ROOT + xpRoot + "/text()");
			if (DSSUtils.isBlank(expectedValue)) {
				expectedValue = defaultExpectedValue ? TRUE : FALSE;
			}
			constraint.setExpectedValue(expectedValue);
			return constraint;
		}
		return null;
	}

	/**
	 * This method returns the constraint object checking a given number against a defined interval
	 *
	 * @param xpRoot
	 * @return
	 */
	private ElementNumberConstraint getElementNumberConstraint(final String xpRoot) {

		final XmlDom elementXmlDom = getElement(xpRoot);
		if (elementXmlDom != null) {

			final String level = elementXmlDom.getAttribute(LEVEL);
			if (DSSUtils.isNotBlank(level)) {

				final String minStr = elementXmlDom.getAttribute(MIN);
				final int min = DSSUtils.parseIntSilently(minStr, 0);
				final String maxStr = elementXmlDom.getAttribute(MAX);
				final int max = DSSUtils.parseIntSilently(maxStr, 999);

				final ElementNumberConstraint constraint = new ElementNumberConstraint(level, min, max);
				return constraint;
			}
		}
		return null;
	}

	@Override
	public BasicValidationProcessValidConstraint getBasicValidationProcessConclusionConstraint() {

		final BasicValidationProcessValidConstraint constraint = new BasicValidationProcessValidConstraint("FAIL");
		constraint.setExpectedValue(TRUE);
		return constraint;
	}

	@Override
	public Constraint getMessageImprintDataFoundConstraint() {

		final String xpRoot = "/Timestamp/MessageImprintDataFound";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getMessageImprintDataIntactConstraint() {

		final String xpRoot = "/Timestamp/MessageImprintDataIntact";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getRevocationTimeConstraint() {

		final String xpRoot = "/Timestamp/RevocationTimeAgainstBestSignatureTime";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getBestSignatureTimeBeforeIssuanceDateOfSigningCertificateConstraint() {

		final String xpRoot = "/Timestamp/BestSignatureTimeBeforeIssuanceDateOfSigningCertificate";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getSigningCertificateValidityAtBestSignatureTimeConstraint() {

		final String xpRoot = "/Timestamp/SigningCertificateValidityAtBestSignatureTime";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getAlgorithmReliableAtBestSignatureTimeConstraint() {

		final String xpRoot = "/Timestamp/AlgorithmReliableAtBestSignatureTime";
		return getBasicConstraint(xpRoot, true);
	}


	@Override
	public Constraint getTimestampCoherenceConstraint() {

		final String xpRoot = "/Timestamp/Coherence";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getTimestampDelaySigningTimePropertyConstraint() {

		final Long timestampDelay = getTimestampDelayTime();
		if (timestampDelay != null && timestampDelay > 0) {

			final Constraint constraint = new Constraint("FAIL");
			constraint.setExpectedValue(TRUE);
			return constraint;
		}
		return null;
	}

	@Override
	public ElementNumberConstraint getCounterSignatureNumberConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedUnsignedQProperties/CounterSignature";
		return getElementNumberConstraint(xpRoot);
	}

	@Override
	public ElementNumberConstraint getSignatureNumberConstraint() {

		final String xpRoot = XP_ROOT + "/GlobalStructure/SignatureNumber";
		return getElementNumberConstraint(xpRoot);
	}

	@Override
	public ElementNumberConstraint getValidSignatureNumberConstraint() {

		final String xpRoot = XP_ROOT + "/GlobalStructure/Valid";
		return getElementNumberConstraint(xpRoot);
	}

	@Override
	public ElementNumberConstraint getSignatureTimestampNumberConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedUnsignedQProperties/SignatureTimestamp";
		return getElementNumberConstraint(xpRoot);
	}

	@Override
	public ElementNumberConstraint getManifestReferenceNumberConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/Manifest/Reference";
		return getElementNumberConstraint(xpRoot);
	}

	@Override
	public Constraint getManifestReferenceDataExistenceConstraint() {

		final String xpRoot = "/MainSignature/Manifest/DataExistence";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public Constraint getManifestReferenceIntactConstraint() {

		final String xpRoot = "/MainSignature/Manifest/ValidReference";
		return getBasicConstraint(xpRoot, true);
	}

	@Override
	public List<Constraint> getISCCustomizedConstraints() {

		final List<Constraint> customizedConstraintList = new ArrayList<Constraint>();
		final List<XmlDom> customizedConstraintXmlDomList = getElements(XP_ROOT + "/MainSignature/SigningCertificate/Customized/Constraint");
		for (final XmlDom constraintXmlDom : customizedConstraintXmlDomList) {

			final String name = constraintXmlDom.getAttribute("Name");
			final String levelString = constraintXmlDom.getAttribute("Level");
			final Constraint.Level level = Constraint.Level.valueOf(levelString);
			if (customConstraintMap == null) {
				throw new DSSException("The customized constraints are not defined!");
			}
			final Constraint constraint = customConstraintMap.get(name);
			if (constraint == null) {
				throw new DSSException("The customized constraint with name '" + name + "' not found!");
			}
			constraint.setLevel(level);
			customizedConstraintList.add(constraint);
		}
		return customizedConstraintList;
	}

	@Override
	public Constraint getCompleteCertificateRefsConstraint() {

		final String xpRoot = "/MainSignature/MandatedUnsignedQProperties/CompleteCertificateRefs";
		return getBasicConstraint(xpRoot, false);
	}

	@Override
	public Constraint getCompleteRevocationRefsConstraint() {

		final String xpRoot = "/MainSignature/MandatedUnsignedQProperties/CompleteRevocationRefs";
		return getBasicConstraint(xpRoot, false);
	}

	@Override
	public ElementNumberConstraint getValidationDataTimestampNumberConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedUnsignedQProperties/ValidationDataTimestamp";
		final ElementNumberConstraint elementNumberConstraint = getElementNumberConstraint(xpRoot);
		if (elementNumberConstraint != null) {
			return elementNumberConstraint;
		}
		return null;
	}

	@Override
	public ElementNumberConstraint getArchiveTimestampNumberConstraint() {

		final String xpRoot = XP_ROOT + "/MainSignature/MandatedUnsignedQProperties/ArchiveTimestamp";
		final ElementNumberConstraint elementNumberConstraint = getElementNumberConstraint(xpRoot);
		if (elementNumberConstraint != null) {
			return elementNumberConstraint;
		}
		return null;
	}

	@Override
	public Constraint getCertificateValuesConstraint() {

		final String xpRoot = "/MainSignature/MandatedUnsignedQProperties/CertificateValues";
		return getBasicConstraint(xpRoot, false);
	}

	@Override
	public Constraint getRevocationValuesConstraint() {

		final String xpRoot = "/MainSignature/MandatedUnsignedQProperties/RevocationValues";
		return getBasicConstraint(xpRoot, false);
	}
}

