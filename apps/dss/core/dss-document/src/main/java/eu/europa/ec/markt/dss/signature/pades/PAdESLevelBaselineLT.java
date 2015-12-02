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

package eu.europa.ec.markt.dss.signature.pades;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.apache.commons.codec.binary.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfObjFactory;
import eu.europa.ec.markt.dss.signature.pdf.model.ModelPdfArray;
import eu.europa.ec.markt.dss.signature.pdf.model.ModelPdfDict;
import eu.europa.ec.markt.dss.signature.pdf.model.ModelPdfStream;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.DefaultAdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.ValidationContext;
import eu.europa.ec.markt.dss.validation102853.cades.CAdESSignature;
import eu.europa.ec.markt.dss.validation102853.crl.CRLToken;
import eu.europa.ec.markt.dss.validation102853.pades.PAdESSignature;
import eu.europa.ec.markt.dss.validation102853.pades.PDFDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

/**
 * Extend a PAdES extension up to LTV.
 *
 * @version $Revision: 2723 $ - $Date: 2013-10-11 11:51:11 +0200 (Fri, 11 Oct 2013) $
 */

class PAdESLevelBaselineLT implements SignatureExtension {

	private static final Logger logger = LoggerFactory.getLogger(PAdESLevelBaselineLT.class);

	private final CertificateVerifier certificateVerifier;
	private final TSPSource tspSource;
	private ModelPdfArray dssCertArray = new ModelPdfArray();
	private ModelPdfArray dssOcspArray = new ModelPdfArray();
	private ModelPdfArray dssCrlArray = new ModelPdfArray();

	PAdESLevelBaselineLT(final TSPSource tspSource, final CertificateVerifier certificateVerifier) {

		this.certificateVerifier = certificateVerifier;
		this.tspSource = tspSource;
	}

	/**
	 * @param document
	 * @param parameters
	 * @return
	 * @throws IOException
	 */
	@Override
	public InMemoryDocument extendSignatures(DSSDocument document, final SignatureParameters parameters) throws DSSException {

		try {

			// check if needed to extends with PAdESLevelBaselineT
			final PDFDocumentValidator pdfDocumentValidator = new PDFDocumentValidator(document);
			pdfDocumentValidator.setCertificateVerifier(certificateVerifier);
			List<AdvancedSignature> signatures = pdfDocumentValidator.getSignatures();
			for (final AdvancedSignature signature : signatures) {

				if (!signature.isDataForSignatureLevelPresent(SignatureLevel.PAdES_BASELINE_T)) {

					final PAdESLevelBaselineT padesLevelBaselineT = new PAdESLevelBaselineT(tspSource);
					document = padesLevelBaselineT.extendSignatures(document, parameters);
					break;
				}
			}

			// create DSS dictionary
			ModelPdfDict dssDictionary = new ModelPdfDict("DSS");
			for (final AdvancedSignature signature : signatures) {
				if (signature instanceof PAdESSignature) {
					PAdESSignature pAdESSignature = (PAdESSignature) signature;
					SignatureValidationCallBack callback = new SignatureValidationCallBack();
					validate(pAdESSignature, callback);
					includeToDssDictionary(dssDictionary, callback);
				}
			}

			addGlobalCertsCrlsOcsps(dssDictionary);

			final ByteArrayOutputStream baos = new ByteArrayOutputStream();

			final PDFSignatureService signatureService = PdfObjFactory.getInstance().newPAdESSignatureService();
			signatureService.addDssDictionary(document.openStream(), baos, dssDictionary);

			final InMemoryDocument inMemoryDocument = new InMemoryDocument(baos.toByteArray());
			inMemoryDocument.setMimeType(MimeType.PDF);
			return inMemoryDocument;
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	private void includeToDssDictionary(ModelPdfDict dssDictionary, SignatureValidationCallBack callback) throws IOException {

		ModelPdfDict vriDictionary = ensureNotNull(dssDictionary, "VRI");

		ModelPdfDict sigVriDictionary = new ModelPdfDict();

		PAdESSignature signature = callback.getSignature();
		final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA1, signature.getCAdESSignature().getCmsSignedData().getEncoded());
		String hexHash = Hex.encodeHexString(digest).toUpperCase();

		if (DSSUtils.isNotEmpty(callback.getCertificates())) {
			ModelPdfArray vriCertArray = new ModelPdfArray();
			for (CertificateToken token : callback.getCertificates()) {
				ModelPdfStream stream = new ModelPdfStream(token.getEncoded());
				vriCertArray.add(stream);
				dssCertArray.add(stream);
			}
			sigVriDictionary.add("Cert", vriCertArray);
		}

		if (DSSUtils.isNotEmpty(callback.getCrls())) {
			ModelPdfArray vriCrlArray = new ModelPdfArray();
			for (CRLToken token : callback.getCrls()) {
				ModelPdfStream stream = new ModelPdfStream(token.getEncoded());
				vriCrlArray.add(stream);
				dssCrlArray.add(stream);
			}
			sigVriDictionary.add("CRL", vriCrlArray);
		}

		if (DSSUtils.isNotEmpty(callback.getOcsps())) {
			ModelPdfArray vriOcspArray = new ModelPdfArray();
			for (OCSPToken token : callback.getOcsps()) {
				ModelPdfStream stream = new ModelPdfStream(token.getEncoded());
				vriOcspArray.add(stream);
				dssOcspArray.add(stream);
			}
			sigVriDictionary.add("OCSP", vriOcspArray);
		}

		vriDictionary.add(hexHash, sigVriDictionary);

	}

	private void addGlobalCertsCrlsOcsps(ModelPdfDict dssDictionary) {

		if (dssCertArray.size() > 0) {
			dssDictionary.add("Certs", dssCertArray);
		}
		if (dssCrlArray.size() > 0) {
			dssDictionary.add("CRLs", dssCrlArray);
		}
		if (dssOcspArray.size() > 0) {
			dssDictionary.add("OCSPs", dssOcspArray);
		}
	}


	private ModelPdfDict ensureNotNull(ModelPdfDict dssDictionary, String dictionaryName) {

		ModelPdfDict dictionary = (ModelPdfDict) dssDictionary.getValues().get(dictionaryName);
		if (dictionary == null) {

			dictionary = new ModelPdfDict();
			dssDictionary.add(dictionaryName, dictionary);
		}
		return dictionary;
	}

	private void validate(PAdESSignature signature, SignatureValidationCallBack validationCallback) {

		CAdESSignature cadesSignature = signature.getCAdESSignature();
		ValidationContext validationContext = cadesSignature.getSignatureValidationContext(certificateVerifier);
		DefaultAdvancedSignature.RevocationDataForInclusion revocationsForInclusionInProfileLT = cadesSignature.getRevocationDataForInclusion(validationContext);

		validationCallback.setSignature(signature);
		validationCallback.setCrls(revocationsForInclusionInProfileLT.crlTokens);
		validationCallback.setOcsps(revocationsForInclusionInProfileLT.ocspTokens);

		Set<CertificateToken> certs = new HashSet<CertificateToken>(cadesSignature.getCertificates());
		validationCallback.setCertificates(certs);
	}

	class SignatureValidationCallBack {

		private PAdESSignature signature;
		private List<CRLToken> crls;
		private List<OCSPToken> ocsps;
		private Set<CertificateToken> certificates;

		public PAdESSignature getSignature() {
			return signature;
		}

		public void setSignature(PAdESSignature signature) {
			this.signature = signature;
		}

		public List<CRLToken> getCrls() {
			return crls;
		}

		public void setCrls(List<CRLToken> crls) {
			this.crls = crls;
		}

		public List<OCSPToken> getOcsps() {
			return ocsps;
		}

		public void setOcsps(List<OCSPToken> ocsps) {
			this.ocsps = ocsps;
		}

		public Set<CertificateToken> getCertificates() {
			return certificates;
		}

		public void setCertificates(Set<CertificateToken> certificates) {
			this.certificates = certificates;
		}
	}
}
