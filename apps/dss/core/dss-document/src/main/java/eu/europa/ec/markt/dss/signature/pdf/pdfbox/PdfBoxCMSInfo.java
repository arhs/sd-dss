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

package eu.europa.ec.markt.dss.signature.pdf.pdfbox;

import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;

abstract class PdfBoxCMSInfo implements PdfSignatureOrDocTimestampInfo {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxCMSInfo.class);
	private final PdfDssDict dssDictionary;
	private final Date signingDate;
	private final String location;
	private final String contactInfo;
	private final String reason;
	private final String subFilter;
	private final int[] signatureByteRange;

	private final byte[] cms;

	/**
	 * The original signed pdf document
	 */
	private final byte[] signedBytes;

	private boolean verified;
	private SignatureCryptographicVerification verifyResult;
	private String uniqueId;

	private Set<PdfSignatureOrDocTimestampInfo> outerSignatures = new HashSet<PdfSignatureOrDocTimestampInfo>();

	/**
	 * @param signature     The signature object
	 * @param dssDictionary the DSS dictionary
	 * @param cms           the signature binary
	 * @param signedContent the signed content
	 */
	PdfBoxCMSInfo(PDSignature signature, PdfDssDict dssDictionary, byte[] cms, byte[] signedContent) {
		this.cms = cms;
		this.location = signature.getLocation();
		this.reason = signature.getReason();
		this.contactInfo = signature.getContactInfo();
		this.subFilter = signature.getSubFilter();
		this.signingDate = signature.getSignDate() != null ? signature.getSignDate().getTime() : null;
		this.signatureByteRange = signature.getByteRange();
		this.dssDictionary = dssDictionary;
		this.signedBytes = signedContent;
	}

	@Override
	public SignatureCryptographicVerification checkIntegrity() {

		if (!verified) {

			verifyResult = checkIntegrityOnce();
			LOG.debug("Verify embedded CAdES Signature on signedBytes size {}. Signature intact: {}", signedBytes.length, verifyResult);
			verified = true;
		}
		return verifyResult;
	}

	protected abstract SignatureCryptographicVerification checkIntegrityOnce();

	/**
	 * @return the byte of the originally signed document
	 */
	@Override
	public byte[] getSignedDocumentBytes() {
		return signedBytes;
	}

	@Override
	public byte[] getOriginalBytes() {
		final int length = signatureByteRange[1];
		final byte[] result = new byte[length];
		System.arraycopy(signedBytes, 0, result, 0, length);
		return result;
	}

	@Override
	public PdfDssDict getDssDictionary() {
		return dssDictionary;
	}

	@Override
	public String uniqueId() {
		if (uniqueId == null) {
			byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, cms);
			uniqueId = Hex.encodeHexString(digest);
	}
		return uniqueId;
	}

	@Override
	public void addOuterSignature(PdfSignatureOrDocTimestampInfo signatureInfo) {
		outerSignatures.add(signatureInfo);
	}

	@Override
	public Set<PdfSignatureOrDocTimestampInfo> getOuterSignatures() {
		return Collections.unmodifiableSet(outerSignatures);
	}

	@Override
	public int[] getSignatureByteRange() {
		return signatureByteRange;
	}

	@Override
	public String getLocation() {
		return location;
}

	@Override
	public Date getSigningDate() {
		return signingDate;
	}

	@Override
	public String getContactInfo() {
		return contactInfo;
	}

	@Override
	public String getReason() {
		return reason;
	}

	@Override
	public String getSubFilter() {
		return subFilter;
	}

	@Override
	public String toString() {
		return "PdfBoxCMSInfo [subFilter=" + subFilter + ", uniqueId=" + uniqueId() + ", signatureByteRange=" + Arrays
			  .toString(signatureByteRange) + ", outerSignatures=" + outerSignatures + "]";
	}

}