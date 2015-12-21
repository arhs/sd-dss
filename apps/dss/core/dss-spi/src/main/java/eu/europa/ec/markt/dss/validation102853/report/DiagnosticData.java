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
import java.util.Date;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.TSLConstant;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * This class represents all static data extracted by the process analysing the signature. They are independent from the validation policy to be applied.
 * <p/>
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DiagnosticData extends XmlDom {

	private List<String> signatureIdList;

	public DiagnosticData(final Document document) {
		super(document);
	}

	/**
	 * This method returns the list of the signature id. The result is stored in the local variable.
	 *
	 * @return list of signature ids, is never null, can be empty
	 */
	public List<String> getSignatureIdList() {

		if (signatureIdList == null) {

			signatureIdList = new ArrayList<String>();

			final List<XmlDom> signatures = getElements("/DiagnosticData/Signature");
			for (final XmlDom signature : signatures) {

				final String signatureId = signature.getAttribute("Id");
				signatureIdList.add(signatureId);
			}
		}
		return signatureIdList;
	}

	/**
	 * This method returns the first signature id.
	 *
	 * @return
	 */
	public String getFirstSignatureId() {

		getSignatureIdList();
		if (signatureIdList.size() > 0) {
			return signatureIdList.get(0);
		}
		return null;
	}

	public Date getSignatureDate() {

		final Date signatureDate = getTimeValue("/DiagnosticData/Signature[1]/DateTime/text()");
		//final XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(signatureDate);
		//xmlGregorianCalendar.
		return signatureDate;
	}

	/**
	 * This method returns the claimed signing time.
	 *
	 * @param signatureId The identifier of the signature, for which the date is sought.
	 * @return
	 */
	public Date getSignatureDate(final String signatureId) {

		Date signatureDate = null;
		try {
			signatureDate = getTimeValue("/DiagnosticData/Signature[@Id='%s']/DateTime/text()", signatureId);
		} catch (DSSException e) {

			// returns null if not found
		}
		return signatureDate;
	}

	/**
	 * This method returns the signature format for the given signature.
	 *
	 * @param signatureId The identifier of the signature, for which the format is sought.
	 * @return The signature format
	 */
	public String getSignatureFormat(final String signatureId) {

		String signatureFormat = getValue("/DiagnosticData/Signature[@Id='%s']/SignatureFormat/text()", signatureId);
		return signatureFormat;
	}

	/**
	 * This method returns the {@code DigestAlgorithm} of the first signature.
	 *
	 * @return The {@code DigestAlgorithm} of the first signature
	 */
	public DigestAlgorithm getSignatureDigestAlgorithm() {

		final String signatureDigestAlgorithmName = getValue("/DiagnosticData/Signature[1]/BasicSignature/DigestAlgoUsedToSignThisToken/text()");
		final DigestAlgorithm signatureDigestAlgorithm = DigestAlgorithm.forName(signatureDigestAlgorithmName, null);
		return signatureDigestAlgorithm;
	}

	/**
	 * This method returns the {@code DigestAlgorithm} for the given signature.
	 *
	 * @param signatureId The identifier of the signature, for which the algorithm is sought.
	 * @return The {@code DigestAlgorithm} for the given signature
	 */
	public DigestAlgorithm getSignatureDigestAlgorithm(final String signatureId) {

		final String signatureDigestAlgorithmName = getValue("/DiagnosticData/Signature[@Id='%s']/BasicSignature/DigestAlgoUsedToSignThisToken/text()", signatureId);
		final DigestAlgorithm signatureDigestAlgorithm = DigestAlgorithm.forName(signatureDigestAlgorithmName);
		return signatureDigestAlgorithm;
	}

	/**
	 * This method returns the {@code EncryptionAlgorithm} of the first signature.
	 *
	 * @return The {@code EncryptionAlgorithm} of the first signature
	 */
	public EncryptionAlgorithm getSignatureEncryptionAlgorithm() {

		final String signatureEncryptionAlgorithmName = getValue("/DiagnosticData/Signature[1]/BasicSignature/EncryptionAlgoUsedToSignThisToken/text()");
		final EncryptionAlgorithm signatureEncryptionAlgorithm = EncryptionAlgorithm.forName(signatureEncryptionAlgorithmName, null);
		return signatureEncryptionAlgorithm;
	}

	/**
	 * This method returns the {@code DigestAlgorithm} for the given signature.
	 *
	 * @param signatureId The identifier of the signature, for which the algorithm is sought.
	 * @return The {@code DigestAlgorithm} for the given signature
	 */
	public EncryptionAlgorithm getSignatureEncryptionAlgorithm(final String signatureId) {

		final String signatureEncryptionAlgorithmName = getValue("/DiagnosticData/Signature[@Id='%s']/BasicSignature/EncryptionAlgoUsedToSignThisToken/text()", signatureId);
		final EncryptionAlgorithm signatureEncryptionAlgorithm = EncryptionAlgorithm.forName(signatureEncryptionAlgorithmName);
		return signatureEncryptionAlgorithm;
	}

	/**
	 * This method returns signing certificate dss id for the first signature.
	 *
	 * @return signing certificate dss id.
	 */
	public int getSigningCertificateId() {

		final int signingCertificateId = getIntValue("/DiagnosticData/Signature[1]/SigningCertificate/@Id");
		return signingCertificateId;
	}

	/**
	 * This method returns signing certificate dss id for the given signature.
	 *
	 * @param signatureId The identifier of the signature, for which the signing certificate is sought.
	 * @return signing certificate dss id for the given signature.
	 */
	public int getSigningCertificateId(final String signatureId) {

		final int signingCertificateId = getIntValue("/DiagnosticData/Signature[@Id='%s']/SigningCertificate/@Id", signatureId);
		return signingCertificateId;
	}

	/**
	 * This method indicates if the digest value and the issuer and serial match for the signing certificate .
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the digest value and the issuer and serial match.
	 */
	public boolean isSigningCertificateIdentified(final String signatureId) {

		final boolean digestValueMatch = getBoolValue("/DiagnosticData/Signature[@Id='%s']/SigningCertificate/DigestValueMatch/text()", signatureId);
		final boolean issuerSerialMatch = getBoolValue("/DiagnosticData/Signature[@Id='%s']/SigningCertificate/IssuerSerialMatch/text()", signatureId);
		return digestValueMatch && issuerSerialMatch;
	}

	/**
	 * This method returns the list of certificates in the chain of the main signature.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return list of certificate's dss id for the given signature.
	 */
	public List<Integer> getSignatureCertificateChain(final String signatureId) {

		final ArrayList<Integer> certificateChain = new ArrayList<Integer>();
		final List<XmlDom> certificateId = getElements("/DiagnosticData/Signature[@Id='%s']/CertificateChain/ChainCertificate", signatureId);
		for (final XmlDom xmlDom : certificateId) {

			final String id = xmlDom.getAttribute("Id");
			certificateChain.add(Integer.valueOf(id));
		}
		return certificateChain;
	}

	public String getPolicyId() {

		final String policyId = getValue("/DiagnosticData/Signature[1]/Policy/Id/text()");
		return policyId;
	}

	/**
	 * The identifier of the policy.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return the policy identifier
	 */
	public String getPolicyId(final String signatureId) {

		final String policyId = getValue("/DiagnosticData/Signature[@Id='%s']/Policy/Id/text()", signatureId);
		return policyId;
	}

	/**
	 * This method returns the list of identifier of the timestamps related to the given signature.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return The list of identifier of the timestamps
	 */
	public List<String> getTimestampIdList(final String signatureId) {

		final List<String> timestampIdList = new ArrayList<String>();

		final List<XmlDom> timestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp", signatureId);
		for (final XmlDom timestamp : timestamps) {

			final String timestampId = timestamp.getAttribute("Id");
			timestampIdList.add(timestampId);
		}
		return timestampIdList;
	}

	/**
	 * This method returns the list of identifier of the timestamps related to the given signature.
	 *
	 * @param signatureId   The identifier of the signature.
	 * @param timestampType The {@code TimestampType}
	 * @return The list of identifier of the timestamps
	 */
	public List<String> getTimestampIdList(final String signatureId, final TimestampType timestampType) {

		final List<String> timestampIdList = new ArrayList<String>();

		final List<XmlDom> timestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId, timestampType.name());
		for (final XmlDom timestamp : timestamps) {

			final String timestampId = timestamp.getAttribute("Id");
			timestampIdList.add(timestampId);
		}
		return timestampIdList;
	}

	/**
	 * Indicates if the -B level is technically valid. It means that the signature value is valid.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the signature value is valid
	 */
	public boolean isBLevelTechnicallyValid(final String signatureId) {

		final boolean signatureValueValid = getBoolValue("/DiagnosticData/Signature[@Id='%s']/BasicSignature/SignatureValid/text()", signatureId);
		return signatureValueValid;
	}

	/**
	 * Indicates if there is a signature timestamp.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the signature timestamp is present
	 */
	public boolean isThereTLevel(final String signatureId) {

		final List<XmlDom> timestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId, TimestampType.SIGNATURE_TIMESTAMP.name());
		return timestamps.size() > 0;
	}

	/**
	 * Indicates if the -T level is technically valid. It means that the signature and the digest are valid.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isTLevelTechnicallyValid(final String signatureId) {

		final List<XmlDom> timestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId, TimestampType.SIGNATURE_TIMESTAMP.name());
		for (final XmlDom timestamp : timestamps) {

			final boolean signatureValid = timestamp.getBoolValue("./BasicSignature/SignatureValid/text()");
			final boolean messageImprintIntact = timestamp.getBoolValue("./MessageImprintDataIntact/text()");
			if (signatureValid && messageImprintIntact) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Indicates if there is an -X1 or -X2 timestamp.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the -X1 or -X2 is present
	 */
	public boolean isThereXLevel(final String signatureId) {

		final List<XmlDom> vdroTimestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId,
			  TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.name());
		final List<XmlDom> vdTimestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId,
			  TimestampType.VALIDATION_DATA_TIMESTAMP.name());
		return vdroTimestamps.size() > 0 || vdTimestamps.size() > 0;
	}

	/**
	 * Indicates if the -X level is technically valid. It means that the signature and the digest are valid.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isXLevelTechnicallyValid(final String signatureId) {

		final List<XmlDom> vdroTimestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId,
			  TimestampType.VALIDATION_DATA_REFSONLY_TIMESTAMP.name());
		final List<XmlDom> vdTimestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId,
			  TimestampType.VALIDATION_DATA_TIMESTAMP.name());
		final List<XmlDom> timestamps = new ArrayList<XmlDom>(vdroTimestamps);
		timestamps.addAll(vdroTimestamps);
		for (final XmlDom timestamp : timestamps) {

			final boolean signatureValid = timestamp.getBoolValue("./BasicSignature/SignatureValid/text()");
			final boolean messageImprintIntact = timestamp.getBoolValue("./MessageImprintDataIntact/text()");
			if (signatureValid && messageImprintIntact) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Indicates if there is an archive timestamp.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the archive timestamp is present
	 */
	public boolean isThereALevel(final String signatureId) {

		final List<XmlDom> timestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId, TimestampType.ARCHIVE_TIMESTAMP.name());
		return timestamps.size() > 0;
	}

	/**
	 * Indicates if the -A (-LTA) level is technically valid. It means that the signature of the archive timestamps are valid and their imprint is valid too.
	 *
	 * @param signatureId The identifier of the signature.
	 * @return true if the signature and digest are valid
	 */
	public boolean isALevelTechnicallyValid(final String signatureId) {

		final List<XmlDom> timestamps = getElements("/DiagnosticData/Signature[@Id='%s']/Timestamps/Timestamp[@Type='%s']", signatureId, TimestampType.ARCHIVE_TIMESTAMP.name());
		for (final XmlDom timestamp : timestamps) {

			final boolean signatureValid = timestamp.getBoolValue("./BasicSignature/SignatureValid/text()");
			final boolean messageImprintIntact = timestamp.getBoolValue("./MessageImprintDataIntact/text()");
			if (signatureValid && messageImprintIntact) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Returns the identifier of the timestamp signing certificate.
	 *
	 * @param timestampId timestamp id
	 * @return signing certificate id
	 */
	public int getTimestampSigningCertificateId(final String timestampId) {

		final int signingCertificateId = getIntValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/SigningCertificate/@Id", timestampId);
		return signingCertificateId;
	}

	/**
	 * Returns the digest algorithm used to compute the hash value.
	 *
	 * @param timestampId timestamp id
	 * @return the digest algorithm
	 */
	public Date getTimestampProductionTime(final String timestampId) {

		final Date productionTime = getTimeValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/ProductionTime/text()", timestampId);
		return productionTime;
	}

	/**
	 * Returns the digest algorithm used to compute the hash value.
	 *
	 * @param timestampId timestamp id
	 * @return the digest algorithm
	 */
	public String getTimestampDigestAlgorithm(final String timestampId) {

		final String digestAlgorithm = getValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/SignedDataDigestAlgo/text()", timestampId);
		return digestAlgorithm;
	}

	/**
	 * Returns the result of validation of the timestamp message imprint.
	 *
	 * @param timestampId timestamp id
	 * @return true or false
	 */
	public boolean isTimestampMessageImprintIntact(final String timestampId) {

		final boolean messageImprintIntact = getBoolValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/MessageImprintDataIntact/text()", timestampId);
		return messageImprintIntact;
	}

	/**
	 * Returns the result of validation of the timestamp signature.
	 *
	 * @param timestampId timestamp id
	 * @return
	 */
	public boolean isTimestampSignatureValid(final String timestampId) {

		final boolean signatureValid = getBoolValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/BasicSignature/SignatureValid/text()", timestampId);
		return signatureValid;
	}

	/**
	 * Returns the type of the timestamp.
	 *
	 * @param timestampId timestamp id
	 * @return
	 */
	public String getTimestampType(final String timestampId) {

		final String timestampType = getValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/@Type", timestampId);
		return timestampType;
	}

	public String getTimestampCanonicalizationMethod(final String timestampId) {

		final String canonicalizationMethod = getValue("/DiagnosticData/Signature/Timestamps/Timestamp[@Id='%s']/CanonicalizationMethod/text()", timestampId);
		return canonicalizationMethod;
	}

	/**
	 * This method indicates if the certificate signature is valid and the revocation status is valid.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return certificate validity
	 */
	public boolean isValidCertificate(final int dssCertificateId) {

		final XmlDom certificate = getElement("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']", dssCertificateId);
		final boolean signatureValid = certificate.getBoolValue("./BasicSignature/SignatureValid/text()");
		final boolean revocationValid = certificate.getBoolValue("./Revocation/Status/text()");
		final boolean trusted = certificate.getBoolValue("./Trusted/text()");

		final boolean validity = signatureValid && (trusted ? true : revocationValid);
		return validity;
	}

	/**
	 * This method returns the subject distinguished name for the given dss certificate identifier.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return subject distinguished name
	 */
	public String getCertificateDN(final int dssCertificateId) {

		final String subjectDistinguishedName = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/SubjectDistinguishedName[@Format='RFC2253']/text()",
			  dssCertificateId);
		return subjectDistinguishedName;
	}

	/**
	 * This method returns the issuer distinguished name for the given dss certificate identifier.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return issuer distinguished name
	 */
	public String getCertificateIssuerDN(final int dssCertificateId) {

		final String issuerDistinguishedName = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/IssuerDistinguishedName[@Format='RFC2253']/text()",
			  dssCertificateId);
		return issuerDistinguishedName;
	}

	/**
	 * This method returns the serial number of the given dss certificate identifier.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return serial number
	 */
	public String getCertificateSerialNumber(final int dssCertificateId) {

		final String serialNumber = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/SerialNumber/text()", dssCertificateId);
		return serialNumber;
	}

	/**
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return {@code Date} not after attribute value
	 */
	public Date getCertificateNotAfter(final int dssCertificateId) {

		final Date notAfter = getTimeValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/NotAfter/text()", dssCertificateId);
		return notAfter;
	}

	/**
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return {@code Date} not before attribute value
	 */
	public Date getCertificateNotBefore(final int dssCertificateId) {

		final Date notBefore = getTimeValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/NotBefore/text()", dssCertificateId);
		return notBefore;
	}

	/**
	 * This method returns the validity of the certificate at the validation time.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return serial number
	 */
	public boolean isCertificateValidAtValidationTime(final int dssCertificateId) {

		final boolean validityAtValidationTime = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/ValidityAtValidationTime/text()", dssCertificateId);
		return validityAtValidationTime;
	}

	/**
	 * This method indicates if the certificate is QCP.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCP
	 */
	public boolean isCertificateQCP(final int dssCertificateId) {

		final boolean qcp = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/QCStatement/QCP/text()", dssCertificateId);
		return qcp;
	}

	/**
	 * This method indicates if the certificate is QCPPlus.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCPPlus
	 */
	public boolean isCertificateQCPPlus(final int dssCertificateId) {

		final boolean qcpPlus = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/QCStatement/QCPPlus/text()", dssCertificateId);
		return qcpPlus;
	}

	/**
	 * This method indicates if the certificate is QCC.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCC
	 */
	public boolean isCertificateQCC(final int dssCertificateId) {

		final boolean qcc = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/QCStatement/QCC/text()", dssCertificateId);
		return qcc;
	}

	/**
	 * This method indicates if the certificate is QCSSCD.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCSSCD
	 */
	public boolean isCertificateQCSSCD(final int dssCertificateId) {

		final boolean qcsscd = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/QCStatement/QCSSCD/text()", dssCertificateId);
		return qcsscd;
	}


	/**
	 * This method indicates if the certificate has QCWithSSCD qualification.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCWithSSCD qualification is present
	 */
	public boolean hasCertificateQCWithSSCDQualification(final int dssCertificateId) {

		final String condition = "contains('" + TSLConstant.QC_WITH_SSCD + "', '" + TSLConstant.QC_WITH_SSCD_119612 + "')";
		final String qualification = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/Qualifiers/Qualifier[" + condition + "]/text()",
			  dssCertificateId);
		return !qualification.isEmpty();
	}

	/**
	 * This method indicates if the certificate has QCNoSSCD qualification.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCNoSSCD qualification is present
	 */
	public boolean hasCertificateQCNoSSCDQualification(final int dssCertificateId) {

		final String condition = "contains('" + TSLConstant.QC_NO_SSCD + "', '" + TSLConstant.QC_NO_SSCD_119612 + "')";
		final String qualification = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/Qualifiers/Qualifier[" + condition + "]/text()",
			  dssCertificateId);
		return !qualification.isEmpty();
	}

	/**
	 * This method indicates if the certificate has QCSSCDStatusAsInCert qualification.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCSSCDStatusAsInCert qualification is present
	 */
	public boolean hasCertificateQCSSCDStatusAsInCertQualification(final int dssCertificateId) {

		final String condition = "contains('" + TSLConstant.QCSSCD_STATUS_AS_IN_CERT + "', '" + TSLConstant.QCSSCD_STATUS_AS_IN_CERT_119612 + "')";
		final String qualification = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/Qualifiers/Qualifier[" + condition + "]/text()",
			  dssCertificateId);
		return !qualification.isEmpty();
	}

	/**
	 * This method indicates if the certificate has QCForLegalPerson qualification.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return true if QCForLegalPerson qualification is present
	 */
	public boolean hasCertificateQCForLegalPersonQualification(final int dssCertificateId) {

		final String condition = "contains('" + TSLConstant.QC_FOR_LEGAL_PERSON + "', '" + TSLConstant.QC_FOR_LEGAL_PERSON_119612 + "')";
		final String qualification = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/Qualifiers/Qualifier[" + condition + "]/text()",
			  dssCertificateId);
		return !qualification.isEmpty();
	}

	/**
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return This method returns the {@code List} of key usage for a given certificate.
	 */
	public List<String> getCertificateKeyUsageList(final int dssCertificateId) {

		List<String> keyUsageIdList = new ArrayList<String>();
		final List<XmlDom> keyUsages = getElements("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/KeyUsageBits/KeyUsage", dssCertificateId);
		for (final XmlDom keyUsage : keyUsages) {

			final String keyUsageText = keyUsage.getText();
			keyUsageIdList.add(keyUsageText);
		}
		return keyUsageIdList;
	}

	/**
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return This method returns the {@code List} of policies for a given certificate.
	 */
	public List<String> getCertificatePolicyList(final int dssCertificateId) {

		List<String> policyIdList = new ArrayList<String>();
		final List<XmlDom> policies = getElements("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/CertificatePolicies/CertificatePolicy", dssCertificateId);
		for (final XmlDom policy : policies) {

			final String policyText = policy.getText();
			policyIdList.add(policyText);
		}
		return policyIdList;
	}

	/**
	 * This method returns the associated TSPServiceName.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return TSPServiceName
	 */
	public String getCertificateTSPServiceName(final int dssCertificateId) {

		final String tspServiceName = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/TSPServiceName/text()", dssCertificateId);
		return tspServiceName;
	}

	public String getCertificateTSPServiceStatus(final int dssCertificateId) {

		final String TSPServiceStatus = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/Status/text()", dssCertificateId);
		return TSPServiceStatus;
	}

	public String getCertificateTSPServiceStartDate(final int dssCertificateId) {

		final String TSPServiceStartDate = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/StartDate/text()", dssCertificateId);
		return TSPServiceStartDate;
	}

	public List<String> getCertificateTSPServiceQualifiers(final int dssCertificateId) {

		List<String> tspServiceQualifiers = new ArrayList<String>();
		final List<XmlDom> TSPServiceQualifiers = getElements("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/Qualifiers/Qualifier",
			  dssCertificateId);

		for (XmlDom tspServiceQualifier : TSPServiceQualifiers) {
			tspServiceQualifiers.add(tspServiceQualifier.getText());
		}
		return tspServiceQualifiers;
	}

	/**
	 * This method indicates if the associated trusted list is well signed.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return TSPServiceName
	 */
	public boolean isCertificateRelatedTSLWellSigned(final int dssCertificateId) {

		final boolean wellSigned = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/TrustedServiceProvider/WellSigned/text()", dssCertificateId);
		return wellSigned;
	}

	/**
	 * This method returns the revocation source for the given certificate.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return revocation source
	 */
	public String getCertificateRevocationSource(final int dssCertificateId) {

		final String certificateRevocationSource = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/Revocation/Source/text()", dssCertificateId);
		return certificateRevocationSource;
	}

	/**
	 * This method returns the revocation status for the given certificate.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return revocation status
	 */
	public boolean getCertificateRevocationStatus(final int dssCertificateId) {

		final boolean certificateRevocationStatus = getBoolValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/Revocation/Status/text()", dssCertificateId);
		return certificateRevocationStatus;
	}

	/**
	 * This method returns the revocation reason for the given certificate.
	 *
	 * @param dssCertificateId DSS certificate identifier to be checked
	 * @return revocation reason
	 */
	public String getCertificateRevocationReason(int dssCertificateId) {

		final String revocationReason = getValue("/DiagnosticData/UsedCertificates/Certificate[@Id='%s']/Revocation/Reason/text()", dssCertificateId);
		return revocationReason;
	}

	public String getErrorMessage(final String signatureId) {

		final String errorMessage = getValue("/DiagnosticData/Signature[@Id='%s']/ErrorMessage/text()", signatureId);
		return errorMessage;
	}

	public List<String> getTrueQCStatements() {

		List<String> trueQcStatements = new ArrayList<String>();
		final List<XmlDom> qcStatements = getElements("/DiagnosticData/UsedCertificates/Certificate/QCStatement");
		for (XmlDom qcStatement : qcStatements) {
			NodeList qcNodes = qcStatement.getRootElement().getChildNodes();
			for (int i = 0; i < qcNodes.getLength(); ++i) {
				if (qcNodes.item(i).getTextContent().toLowerCase().equals("true")) {
					trueQcStatements.add(qcNodes.item(i).getNodeName());
				}
			}
		}
		return trueQcStatements;
	}

	public List<XmlDom> getSignatureManifestReferences(final String signatureId) {

//		final List<XmlDom> references = getElements("/DiagnosticData/Signature[@Id='%s']/BasicSignature/References/Reference[@Type='http://www.w3.org/2000/09/xmldsig#Manifest']/ManifestReferences/Reference", signatureId);
		final List<XmlDom> references = getElements("/dss:DiagnosticData/dss:Signature[@Id='%s']/dss:BasicSignature/dss:References/dss:Reference[@Type='http://www.w3.org/2000/09/xmldsig#Manifest']/dss:ManifestReferences/dss:Reference", signatureId);
		return references;
	}
}