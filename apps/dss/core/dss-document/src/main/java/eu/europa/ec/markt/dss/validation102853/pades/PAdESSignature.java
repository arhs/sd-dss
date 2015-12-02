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

package eu.europa.ec.markt.dss.validation102853.pades;

import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.pdf.PdfDocTimestampInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.ec.markt.dss.signature.pdf.pdfbox.PdfDssDict;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CAdESCertificateSource;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.DefaultAdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.SignatureForm;
import eu.europa.ec.markt.dss.validation102853.SignaturePolicy;
import eu.europa.ec.markt.dss.validation102853.TimestampReference;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.bean.CandidatesForSigningCertificate;
import eu.europa.ec.markt.dss.validation102853.bean.CertifiedRole;
import eu.europa.ec.markt.dss.validation102853.bean.CommitmentType;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureProductionPlace;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateRef;
import eu.europa.ec.markt.dss.validation102853.crl.CRLRef;
import eu.europa.ec.markt.dss.validation102853.crl.OfflineCRLSource;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPRef;
import eu.europa.ec.markt.dss.validation102853.ocsp.OfflineOCSPSource;

/**
 * Implementation of AdvancedSignature for PAdES
 *
 * @version $Revision: 1849 $ - $Date: 2013-04-04 17:51:32 +0200 (Thu, 04 Apr 2013) $
 */
public class PAdESSignature extends DefaultAdvancedSignature {

	private static final Logger LOG = LoggerFactory.getLogger(PAdESSignature.class);

	private final DSSDocument document;
	private final PdfDssDict dssDictionary;

	private final CAdESSignature cadesSignature;
	private final List<TimestampToken> cadesSignatureTimestamps;

	private final PdfSignatureInfo pdfSignatureInfo;

	private PAdESCertificateSource padesCertSources;

	/**
	 * This list represents all digest algorithms used to calculate the digest values of certificates.
	 */
	private Set<DigestAlgorithm> usedCertificatesDigestAlgorithms = new HashSet<DigestAlgorithm>();

	/**
	 * The default constructor for PAdESSignature.
	 *
	 * @param document
	 * @param pdfSignatureInfo
	 * @param certPool
	 * @throws DSSException
	 */
	protected PAdESSignature(final DSSDocument document, final PdfSignatureInfo pdfSignatureInfo, final CertificatePool certPool) throws DSSException {

		super(certPool);
		this.document = document;
		this.dssDictionary = pdfSignatureInfo.getDssDictionary();
		this.cadesSignature = pdfSignatureInfo.getCades();
		this.cadesSignatureTimestamps = cadesSignature.getSignatureTimestamps();
		this.pdfSignatureInfo = pdfSignatureInfo;
		cadesSignature.setPadesSigningTime(getSigningTime());
	}

	@Override
	public SignatureForm getSignatureForm() {

		return SignatureForm.PAdES;
	}

	@Override
	public EncryptionAlgorithm getEncryptionAlgorithm() {

		return cadesSignature.getEncryptionAlgorithm();
	}

	@Override
	public DigestAlgorithm getDigestAlgorithm() {

		return cadesSignature.getDigestAlgorithm();
	}

	@Override
	public PAdESCertificateSource getCertificateSource() {

		if (padesCertSources == null) {

			final CAdESCertificateSource cadesCertSource = cadesSignature.getCertificateSource();
			padesCertSources = new PAdESCertificateSource(dssDictionary, cadesCertSource, certPool);
		}
		return padesCertSources;
	}

	@Override
	public OfflineCRLSource getCRLSource() {

		if (offlineCRLSource == null) {
			offlineCRLSource = new PAdESCRLSource(dssDictionary);
		}
		return offlineCRLSource;
	}

	@Override
	public OfflineOCSPSource getOCSPSource() {

		if (offlineOCSPSource == null) {
			offlineOCSPSource = new PAdESOCSPSource(dssDictionary);
		}
		return offlineOCSPSource;
	}

	@Override
	public CandidatesForSigningCertificate getCandidatesForSigningCertificate() {

		return cadesSignature.getCandidatesForSigningCertificate();
	}

	@Override
	public Date getSigningTime() {
			return pdfSignatureInfo.getSigningDate();
		}

	@Override
	public SignaturePolicy getPolicyId() {

		return cadesSignature.getPolicyId();
	}

	@Override
	public SignatureProductionPlace getSignatureProductionPlace() {

		String location = pdfSignatureInfo.getLocation();
		if (StringUtils.isBlank(location)) {
			return cadesSignature.getSignatureProductionPlace();
		} else {
			SignatureProductionPlace signatureProductionPlace = new SignatureProductionPlace();
			signatureProductionPlace.setCountryName(location);
			return signatureProductionPlace;
		}
	}

	@Override
	public String getContentType() {
		return MimeType.PDF.getMimeTypeString();
	}

	@Override
	public String getContentIdentifier() {
		return null;
	}

	@Override
	public String getContentHints() {
		return null;
	}

	@Override
	public String[] getClaimedSignerRoles() {

		return cadesSignature.getClaimedSignerRoles();
	}

	@Override
	public List<CertifiedRole> getCertifiedSignerRoles() {
		return null;
	}

	@Override
	public List<TimestampToken> getContentTimestamps() {

		final List<TimestampToken> contentTimestamps = cadesSignature.getContentTimestamps();
		return contentTimestamps;
	}

	@Override
	public byte[] getContentTimestampData(final TimestampToken timestampToken) {

		final byte[] contentTimestampData = cadesSignature.getContentTimestampData(timestampToken);
		return contentTimestampData;
	}

	@Override
	public List<TimestampToken> getSignatureTimestamps() {

		final List<TimestampToken> result = new ArrayList<TimestampToken>();
		result.addAll(cadesSignatureTimestamps);
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp() && (outerSignature instanceof PdfDocTimestampInfo)) {

				final PdfDocTimestampInfo pdfBoxTimestampInfo = (PdfDocTimestampInfo) outerSignature;
				// do not return this timestamp if it's an archive timestamp
				final TimestampToken timestampToken = pdfBoxTimestampInfo.getTimestampToken();
				if (timestampToken.getTimeStampType() == TimestampType.SIGNATURE_TIMESTAMP) {

					timestampToken.setTimestampedReferences(cadesSignature.getSignatureTimestampedReferences());
					result.add(timestampToken);
				}
			}
		}
		return Collections.unmodifiableList(result);
	}

	@Override
	public List<TimestampToken> getTimestampsX1() {

      /* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public List<TimestampToken> getTimestampsX2() {

      /* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public List<TimestampToken> getArchiveTimestamps() {

		final List<TimestampToken> archiveTimestampTokenList = new ArrayList<TimestampToken>();
		final List<String> timestampedTimestamps = new ArrayList<String>();
		final Set<PdfSignatureOrDocTimestampInfo> outerSignatures = pdfSignatureInfo.getOuterSignatures();
		usedCertificatesDigestAlgorithms.add(DigestAlgorithm.SHA1);
		for (final PdfSignatureOrDocTimestampInfo outerSignature : outerSignatures) {

			if (outerSignature.isTimestamp()) {

			PdfDocTimestampInfo pdfBoxTimestampInfo = (PdfDocTimestampInfo) outerSignature;
			// return this timestamp if it's an archive timestamp
			final TimestampToken timestampToken = pdfBoxTimestampInfo.getTimestampToken();
			if (timestampToken.getTimeStampType() == TimestampType.ARCHIVE_TIMESTAMP) {

				final List<TimestampReference> references = cadesSignature.getSignatureTimestampedReferences();
				for (final String timestampId : timestampedTimestamps) {

					final TimestampReference signatureReference_ = new TimestampReference(timestampId);
					references.add(signatureReference_);
				}
				final List<CertificateToken> certificates = getCertificates();
				for (final CertificateToken certificate : certificates) {
						references.add(createCertificateTimestampReference(certificate));
				}
				timestampToken.setTimestampedReferences(references);
				archiveTimestampTokenList.add(timestampToken);
			}
			timestampedTimestamps.add(String.valueOf(timestampToken.getDSSId()));
		}

		}
		return Collections.unmodifiableList(archiveTimestampTokenList);
	}

	private TimestampReference createCertificateTimestampReference(CertificateToken certificate) {

		final byte[] certificateDigest = DSSUtils.digest(DigestAlgorithm.SHA1, certificate.getEncoded());
		final TimestampReference reference = new TimestampReference(DigestAlgorithm.SHA1.name(), DSSUtils.base64Encode(certificateDigest));
		return reference;
	}

	@Override
	public List<CertificateToken> getCertificates() {
		return getCertificateSource().getCertificates();
	}

	@Override
	public SignatureCryptographicVerification checkSignatureIntegrity() {

		if (signatureCryptographicVerification != null) {
			return signatureCryptographicVerification;
		}
		signatureCryptographicVerification = pdfSignatureInfo.checkIntegrity();
		return signatureCryptographicVerification;
	}

	@Override
	public void checkSigningCertificate() {

		// TODO-Bob (13/07/2014):
	}

	@Override
	public List<AdvancedSignature> getCounterSignatures() {

      /* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public List<CertificateRef> getCertificateRefs() {
		return cadesSignature.getCertificateRefs();
	}

	@Override
	public List<CRLRef> getCRLRefs() {
		return cadesSignature.getCRLRefs();
	}

	@Override
	public List<OCSPRef> getOCSPRefs() {
		return cadesSignature.getOCSPRefs();
	}

	@Override
	public byte[] getSignatureTimestampData(final TimestampToken timestampToken, String canonicalizationMethod) {
		if (cadesSignatureTimestamps.contains(timestampToken)) {
			return cadesSignature.getSignatureTimestampData(timestampToken, null);
		} else {
			for (final PdfSignatureOrDocTimestampInfo signatureInfo : pdfSignatureInfo.getOuterSignatures()) {
				if (signatureInfo instanceof PdfDocTimestampInfo) {
					PdfDocTimestampInfo pdfTimestampInfo = (PdfDocTimestampInfo) signatureInfo;
					if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
						final byte[] signedDocumentBytes = pdfTimestampInfo.getSignedDocumentBytes();
						return signedDocumentBytes;
					}
				}
			}
		}
		throw new DSSException("Timestamp Data not found");
	}

	@Override
	public byte[] getTimestampX1Data(final TimestampToken timestampToken, String canonicalizationMethod) {

      /* Not applicable for PAdES */
		return null;
	}

	@Override
	public byte[] getTimestampX2Data(final TimestampToken timestampToken, String canonicalizationMethod) {

      /* Not applicable for PAdES */
		return null;
	}

	/**
	 * @return the CAdES signature underlying this PAdES signature
	 */
	public CAdESSignature getCAdESSignature() {

		return cadesSignature;
	}

	@Override
	public byte[] getArchiveTimestampData(TimestampToken timestampToken, String canonicalizationMethod) {
		for (final PdfSignatureOrDocTimestampInfo signatureInfo : pdfSignatureInfo.getOuterSignatures()) {
				if (signatureInfo instanceof PdfDocTimestampInfo) {
					PdfDocTimestampInfo pdfTimestampInfo = (PdfDocTimestampInfo) signatureInfo;
					if (pdfTimestampInfo.getTimestampToken().equals(timestampToken)) {
						final byte[] signedDocumentBytes = pdfTimestampInfo.getSignedDocumentBytes();
						return signedDocumentBytes;
					}
				}
			}
		throw new DSSException("Timestamp Data not found");
	}

	@Override
	public String getId() {
		String cadesId = cadesSignature.getId();
		return cadesId + getDigestOfByteRange();
	}

	private String getDigestOfByteRange() {
		int[] signatureByteRange = pdfSignatureInfo.getSignatureByteRange();
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		for (int i : signatureByteRange) {
			baos.write(i);
		}
		return DSSUtils.getMD5Digest(baos);
	}

	@Override
	public List<TimestampReference> getTimestampedReferences() {

      /* Not applicable for PAdES */
		return Collections.emptyList();
	}

	@Override
	public Set<DigestAlgorithm> getUsedCertificatesDigestAlgorithms() {

		return usedCertificatesDigestAlgorithms;
	}

	@Override
	public boolean isDataForSignatureLevelPresent(SignatureLevel signatureLevel) {

		boolean dataForLevelPresent = true;
		final List<TimestampToken> signatureTimestamps = getSignatureTimestamps();
		switch (signatureLevel) {
			case PAdES_BASELINE_LTA:
				dataForLevelPresent = DSSUtils.isNotEmpty(getArchiveTimestamps());
				dataForLevelPresent &= (((signatureTimestamps != null) && (!signatureTimestamps.isEmpty())));
				break;
			case PAdES_102778_LTV:
				dataForLevelPresent = DSSUtils.isNotEmpty(getArchiveTimestamps());
				break;
			case PAdES_BASELINE_LT:
				dataForLevelPresent &= hasDSSDictionary();
				// break omitted purposely
			case PAdES_BASELINE_T:
				dataForLevelPresent &= (((signatureTimestamps != null) && (!signatureTimestamps.isEmpty())));
				// break omitted purposely
			case PAdES_BASELINE_B:
				dataForLevelPresent &= (pdfSignatureInfo != null);
				break;
			default:
				throw new IllegalArgumentException("Unknown level " + signatureLevel);
		}
		LOG.debug("Level {} found on document {} = {}", new Object[]{signatureLevel, document.getName(), dataForLevelPresent});
		return dataForLevelPresent;
	}

	@Override
	public Set<SignatureLevel> getSignatureLevels_() {

		Set<SignatureLevel> levels = new HashSet<SignatureLevel>();
		levels.add(SignatureLevel.PDF_NOT_ETSI);
		if (hasLTAProfile()) {
			levels.add(SignatureLevel.PAdES_BASELINE_LTA);
		}
		if (hasLTVProfile()) {
			levels.add(SignatureLevel.PAdES_102778_LTV);
		}
		if (hasLTProfile()) {
			levels.add(SignatureLevel.PAdES_BASELINE_LT);
		}
		if (hasTProfile()) {
			levels.add(SignatureLevel.PAdES_BASELINE_T);
		}
		if (hasBProfile()) {
			levels.add(SignatureLevel.PAdES_BASELINE_B);
		}
		return levels;
	}

	/**
	 * Checks the presence of ... segment in the signature, what is the proof -B profile existence
	 *
	 * @return
	 */
	public boolean hasBProfile() {

		final boolean dataForProfilePresent = (pdfSignatureInfo != null);
		return dataForProfilePresent;
	}

	/**
	 * Checks the presence of SignatureTimeStamp segment in the signature, what is the proof -T profile existence
	 *
	 * @return
	 */
	public boolean hasTProfile() {

		final boolean dataForProfilePresent = (((signatureTimestamps != null) && (!signatureTimestamps.isEmpty())));
		return dataForProfilePresent;
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -LTA profile existence
	 *
	 * @return true if -LTA extension is present
	 */
	public boolean hasLTAProfile() {

		boolean dataForProfilePresent = DSSUtils.isNotEmpty(getArchiveTimestamps());
		dataForProfilePresent &= (((signatureTimestamps != null) && (!signatureTimestamps.isEmpty())));
		return dataForProfilePresent;
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -LT profile existence
	 *
	 * @return true if -LT extension is present
	 */
	public boolean hasLTProfile() {

		final boolean dataForProfilePresent = hasDSSDictionary();
		return dataForProfilePresent;
	}

	/**
	 * Checks the presence of CertificateValues and RevocationValues segments in the signature, what is the proof -LTV profile existence
	 *
	 * @return true if -LTV extension is present
	 */
	public boolean hasLTVProfile() {

		boolean dataForProfilePresent = DSSUtils.isNotEmpty(getArchiveTimestamps());
		return dataForProfilePresent;
	}

	@Override
	public SignatureLevel[] getSignatureLevels() {
		return new SignatureLevel[]{SignatureLevel.PAdES_102778_LTV, SignatureLevel.PAdES_BASELINE_LTA, SignatureLevel.PAdES_BASELINE_LT, SignatureLevel.PAdES_BASELINE_T, SignatureLevel.PAdES_BASELINE_B, SignatureLevel.PDF_NOT_ETSI,};
	}

	private boolean hasDSSDictionary() {
		return pdfSignatureInfo.getDssDictionary() != null;
	}

	@Override
	public List<CommitmentType> getCommitmentTypeIndication() {
		return cadesSignature.getCommitmentTypeIndication();
	}

	public boolean hasOuterSignatures() {
		return !pdfSignatureInfo.getOuterSignatures().isEmpty();
	}

	public PdfSignatureInfo getPdfSignatureInfo() {
		return pdfSignatureInfo;
	}
}
