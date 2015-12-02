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

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfDocTimestampInfo;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
class PdfBoxDocTimestampInfo extends PdfBoxCMSInfo implements PdfDocTimestampInfo {

	private static final Logger logger = LoggerFactory.getLogger(PdfBoxDocTimestampInfo.class);

	private final TimestampToken timestampToken;

	/**
	 * @param validationCertPool
	 * @param signature
	 * @param dssDictionary      the DSS dictionary
	 * @param cms                the CMS (CAdES) bytes
	 * @param signedContent
	 * @param isArchiveTimestamp
	 * @throws DSSException
	 */
	PdfBoxDocTimestampInfo(CertificatePool validationCertPool, PDSignature signature, PdfDssDict dssDictionary, byte[] cms, byte[] signedContent,
	                       boolean isArchiveTimestamp) throws DSSException {
		super(signature, dssDictionary, cms, signedContent);
		try {
			TimeStampToken timeStampToken = new TimeStampToken(new CMSSignedData(cms));

			TimestampType timestampType = TimestampType.SIGNATURE_TIMESTAMP;
			if (isArchiveTimestamp) {
				timestampType = TimestampType.ARCHIVE_TIMESTAMP;
			}
			timestampToken = new TimestampToken(timeStampToken, timestampType, validationCertPool);
			logger.debug("Created PdfBoxDocTimestampInfo {} : {}", timestampType, uniqueId());
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	@Override
	public SignatureCryptographicVerification checkIntegrityOnce() {

		final SignatureCryptographicVerification signatureCryptographicVerification = new SignatureCryptographicVerification();
		signatureCryptographicVerification.setReferenceDataFound(false);
		signatureCryptographicVerification.setReferenceDataIntact(false);
		signatureCryptographicVerification.setSignatureIntact(false);
		if (getSignedDocumentBytes() != null) {
			signatureCryptographicVerification.setReferenceDataFound(true);
		}
		signatureCryptographicVerification.setReferenceDataIntact(timestampToken.matchData(getSignedDocumentBytes()));
		signatureCryptographicVerification.setSignatureIntact(timestampToken.isSignatureValid());
		return signatureCryptographicVerification;
	}

	@Override
	public X509Certificate getSigningCertificate() {

		final CertificateToken signingCertificate = timestampToken.getIssuerToken();
		return signingCertificate == null ? null : signingCertificate.getCertificate();
	}

	@Override
	public boolean isTimestamp() {
		return true;
	}

	@Override
	public TimestampToken getTimestampToken() {
		return timestampToken;
	}
}
