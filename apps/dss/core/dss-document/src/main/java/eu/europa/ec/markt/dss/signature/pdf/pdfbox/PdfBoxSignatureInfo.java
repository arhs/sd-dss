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
import java.security.cert.X509Certificate;

import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.cms.CMSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureInfo;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.bean.SignatureCryptographicVerification;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;

class PdfBoxSignatureInfo extends PdfBoxCMSInfo implements PdfSignatureInfo {

	private static final Logger LOG = LoggerFactory.getLogger(PdfBoxSignatureInfo.class);
	private CAdESSignature cades;

	/**
	 * @param validationCertPool
	 * @param dssDictionary      the DSS dictionary
	 * @param cms                the CMS (CAdES) bytes
	 * @param originalBytes      the original bytes of the whole signed document
	 * @throws IOException
	 */
	PdfBoxSignatureInfo(CertificatePool validationCertPool, PDSignature signature, PdfDssDict dssDictionary, byte[] cms, byte[] originalBytes) throws IOException {

		super(signature, dssDictionary, cms, originalBytes);
		try {
			cades = new CAdESSignature(cms, validationCertPool);
			final InMemoryDocument detachedContent = new InMemoryDocument(getSignedDocumentBytes());
			cades.setDetachedContents(detachedContent);
			cades.setPadesSigningTime(getSigningDate());
		} catch (CMSException e) {
			throw new IOException(e);
		}
	}

	@Override
	protected SignatureCryptographicVerification checkIntegrityOnce() {
		return cades.checkSignatureIntegrity();
	}

	@Override
	public X509Certificate getSigningCertificate() {
		CertificateToken signingCertificate = cades.getSigningCertificateToken();
		return signingCertificate == null ? null : signingCertificate.getCertificate();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) {
			return true;
		}
		if (!(o instanceof PdfBoxSignatureInfo)) {
			return false;
		}
		if (!super.equals(o)) {
			return false;
		}


		PdfBoxSignatureInfo that = (PdfBoxSignatureInfo) o;

		if (!cades.equals(that.cades)) {
			return false;
		}

		return true;
	}

	@Override
	public int hashCode() {
		int result = super.hashCode();
		result = (31 * result) + cades.hashCode();
		return result;
	}

	@Override
	public boolean isTimestamp() {
		return false;
	}

	@Override
	public CAdESSignature getCades() {
		return cades;
	}
}
