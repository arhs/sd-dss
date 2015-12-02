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

import java.awt.*;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.exceptions.COSVisitorException;
import org.apache.pdfbox.exceptions.SignatureException;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSigProperties;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.visible.PDVisibleSignDesigner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSPDFUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.SignatureImageParameters;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.pades.visible.ImageFactory;
import eu.europa.ec.markt.dss.signature.pdf.PDFSignatureService;
import eu.europa.ec.markt.dss.signature.pdf.PdfDict;
import eu.europa.ec.markt.dss.signature.pdf.PdfDocTimestampInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureOrDocTimestampInfo;
import eu.europa.ec.markt.dss.signature.pdf.PdfSignatureOrDocTimestampInfoComparator;
import eu.europa.ec.markt.dss.signature.pdf.SignatureValidationCallback;
import eu.europa.ec.markt.dss.signature.pdf.model.ModelPdfDict;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.TimestampType;

class PdfBoxSignatureService implements PDFSignatureService {

	private static final Logger logger = LoggerFactory.getLogger(PdfBoxSignatureService.class);

	@Override
	public byte[] digest(final InputStream toSignDocument, final SignatureParameters parameters, final DigestAlgorithm digestAlgorithm) throws DSSException {

		final byte[] signatureValue = DSSUtils.EMPTY_BYTE_ARRAY;
		File toSignFile = null;
		File signedFile = null;
		PDDocument pdDocument = null;
		try {

			toSignFile = DSSPDFUtils.getFileFromPdfData(toSignDocument);

			pdDocument = PDDocument.load(toSignFile);
			PDSignature pdSignature = createSignatureDictionary(parameters);

			signedFile = File.createTempFile("sd-dss-", "-signed.pdf");
			final FileOutputStream fileOutputStream = DSSPDFUtils.getFileOutputStream(toSignFile, signedFile);

			final byte[] digestValue = signDocumentAndReturnDigest(parameters, signatureValue, signedFile, fileOutputStream, pdDocument, pdSignature, digestAlgorithm);
			return digestValue;
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			DSSUtils.delete(toSignFile);
			DSSUtils.delete(signedFile);
			DSSPDFUtils.close(pdDocument);
		}
	}

	@Override
	public void sign(final InputStream pdfData, final byte[] signatureValue, final OutputStream signedStream, final SignatureParameters parameters,
	                 final DigestAlgorithm digestAlgorithm) throws DSSException {

		File toSignFile = null;
		File signedFile = null;
		FileInputStream fileInputStream = null;
		FileInputStream finalFileInputStream = null;
		PDDocument pdDocument = null;
		try {

			toSignFile = DSSPDFUtils.getFileFromPdfData(pdfData);

			pdDocument = PDDocument.load(toSignFile);
			final PDSignature pdSignature = createSignatureDictionary(parameters);

			signedFile = File.createTempFile("sd-dss-", "-signed.pdf");
			final FileOutputStream fileOutputStream = DSSPDFUtils.getFileOutputStream(toSignFile, signedFile);

			signDocumentAndReturnDigest(parameters, signatureValue, signedFile, fileOutputStream, pdDocument, pdSignature, digestAlgorithm);

			finalFileInputStream = new FileInputStream(signedFile);
			DSSUtils.copy(finalFileInputStream, signedStream);
		} catch (IOException e) {
			throw new DSSException(e);
		} finally {
			DSSUtils.closeQuietly(fileInputStream);
			DSSUtils.closeQuietly(finalFileInputStream);
			DSSUtils.delete(toSignFile);
			DSSUtils.delete(signedFile);
			DSSPDFUtils.close(pdDocument);
		}
	}

	private byte[] signDocumentAndReturnDigest(final SignatureParameters parameters, final byte[] signatureBytes, final File signedFile,
	                                           final FileOutputStream fileOutputStream, final PDDocument pdDocument, final PDSignature pdSignature,
	                                           final DigestAlgorithm digestAlgorithm) throws DSSException {

		try {

			final MessageDigest digest = DSSUtils.getMessageDigest(digestAlgorithm);
			// register signature dictionary and sign interface
			SignatureInterface signatureInterface = new SignatureInterface() {

				@Override
				public byte[] sign(InputStream content) throws SignatureException, IOException {

					byte[] b = new byte[4096];
					int count;
					while ((count = content.read(b)) > 0) {
						digest.update(b, 0, count);
					}
					return signatureBytes;
				}
			};

			SignatureOptions options = new SignatureOptions();
			options.setPreferedSignatureSize(parameters.pades().getSignatureSize());

			if (parameters.pades().getImageParameters() != null) {
				fillImageParameters(pdDocument, parameters.pades().getImageParameters(), options);
			}
			pdDocument.addSignature(pdSignature, signatureInterface, options);

			saveDocumentIncrementally(parameters, signedFile, fileOutputStream, pdDocument);
			final byte[] digestValue = digest.digest();
			if (logger.isDebugEnabled()) {
				logger.debug("Digest to be signed: " + DSSUtils.encodeHexString(digestValue));
			}
			fileOutputStream.close();
			return digestValue;
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (SignatureException e) {
			throw new DSSException(e);
		}
	}

	private void fillImageParameters(final PDDocument doc, final SignatureImageParameters imgParams, SignatureOptions options) throws IOException {
		Dimension optimalSize = ImageFactory.getOptimalSize(imgParams);
		PDVisibleSignDesigner visibleSig = new PDVisibleSignDesigner(doc, ImageFactory.create(imgParams), imgParams.getPage());
		visibleSig.xAxis(imgParams.getxAxis()).yAxis(imgParams.getyAxis()).width((float) optimalSize.getWidth()).height((float) optimalSize.getHeight());

		PDVisibleSigProperties signatureProperties = new PDVisibleSigProperties();
		signatureProperties.visualSignEnabled(true).setPdVisibleSignature(visibleSig).buildSignature();

		options.setVisualSignature(signatureProperties);
		options.setPage(imgParams.getPage());
		}

	private PDSignature createSignatureDictionary(final SignatureParameters parameters) {

		final PDSignature signature = new PDSignature();
		signature.setType(getType());
		signature.setName(String.format("SD-DSS Signature %s", parameters.getDeterministicId()));
		signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE); // default filter
		// sub-filter for basic and PAdES Part 2 signatures
		signature.setSubFilter(getSubFilter());

		if (COSName.SIG.equals(getType())) {
			if (DSSUtils.isNotEmpty(parameters.getContactInfo())) {
				signature.setContactInfo(parameters.getContactInfo());
			}
			// TODO-Bob (01/11/2015):
//			if (StringUtils.isNotEmpty(parameters.getLocation())) {
//				signature.setLocation(parameters.getLocation());
//			}

			if (StringUtils.isNotEmpty(parameters.getReason())) {
				signature.setReason(parameters.getReason());
			}
		}

		// the signing date, needed for valid signature
		final Calendar cal = Calendar.getInstance();
		final Date signingDate = parameters.bLevel().getSigningDate();
		cal.setTime(signingDate);
		signature.setSignDate(cal);
		return signature;
	}

	protected COSName getType() {
		return COSName.SIG;
	}

	public void saveDocumentIncrementally(SignatureParameters parameters, File signedFile, FileOutputStream fileOutputStream, PDDocument pdDocument) throws DSSException {

		FileInputStream signedFileInputStream = null;
		try {

			signedFileInputStream = new FileInputStream(signedFile);
			// the document needs to have an ID, if not a ID based on the current system time is used, and then the digest of the signed data is
			// different
			if (pdDocument.getDocumentId() == null) {

				final byte[] documentIdBytes = DSSUtils.digest(DigestAlgorithm.MD5, parameters.bLevel().getSigningDate().toString().getBytes());
				pdDocument.setDocumentId(DSSUtils.toLong(documentIdBytes));
				pdDocument.setDocumentId(0L);
			}
			pdDocument.saveIncremental(signedFileInputStream, fileOutputStream);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (COSVisitorException e) {
			throw new DSSException(e);
		} finally {
			DSSUtils.closeQuietly(signedFileInputStream);
		}
	}

	protected COSName getSubFilter() {
		return PDSignature.SUBFILTER_ETSI_CADES_DETACHED;
	}

	@Override
	public void validateSignatures(CertificatePool validationCertPool, DSSDocument document, SignatureValidationCallback callback) throws DSSException {
		// recursive search of signature
		InputStream inputStream = document.openStream();
		try {
			List<PdfSignatureOrDocTimestampInfo> signaturesFound = getSignatures(validationCertPool, IOUtils.toByteArray(inputStream));
			for (PdfSignatureOrDocTimestampInfo pdfSignatureOrDocTimestampInfo : signaturesFound) {
			callback.validate(pdfSignatureOrDocTimestampInfo);
		}
		} catch (IOException e) {
			logger.error("Cannot validate signatures : " + e.getMessage(), e);
	}
		DSSUtils.closeQuietly(inputStream);
	}

	private List<PdfSignatureOrDocTimestampInfo> getSignatures(CertificatePool validationCertPool, byte[] originalBytes) {
		List<PdfSignatureOrDocTimestampInfo> signatures = new ArrayList<PdfSignatureOrDocTimestampInfo>();
		ByteArrayInputStream bais = null;
		PDDocument doc = null;
		try {

			bais = new ByteArrayInputStream(originalBytes);
			doc = PDDocument.load(bais);

			List<PDSignature> pdSignatures = doc.getSignatureDictionaries();
			if (DSSUtils.isNotEmpty(pdSignatures)) {
				logger.debug("{} signature(s) found", pdSignatures.size());

				PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSDictionary(), doc);
				PdfDssDict dssDictionary = PdfDssDict.build(catalog);

				for (PDSignature signature : pdSignatures) {
					String subFilter = signature.getSubFilter();
					byte[] cms = signature.getContents(originalBytes);

					if (StringUtils.isEmpty(subFilter) || ArrayUtils.isEmpty(cms)) {
						logger.warn("Wrong signature with empty subfilter or cms.");
					continue;
				}

					byte[] signedContent = signature.getSignedContent(originalBytes);
					int[] byteRange = signature.getByteRange();

					PdfSignatureOrDocTimestampInfo signatureInfo = null;
					if (PdfBoxDocTimeStampService.SUB_FILTER_ETSI_RFC3161.getName().equals(subFilter)) {
						boolean isArchiveTimestamp = false;

						// LT or LTA
						if (dssDictionary != null) {
							// check is DSS dictionary already exist
							if (isDSSDictionaryPresentInPreviousRevision(getOriginalBytes(byteRange, signedContent))) {
								isArchiveTimestamp = true;
							}
						}

						signatureInfo = new PdfBoxDocTimestampInfo(validationCertPool, signature, dssDictionary, cms, signedContent, isArchiveTimestamp);
					} else {
						signatureInfo = new PdfBoxSignatureInfo(validationCertPool, signature, dssDictionary, cms, signedContent);
					}

					if (signatureInfo != null) {
						signatures.add(signatureInfo);
					}
				}
				Collections.sort(signatures, new PdfSignatureOrDocTimestampInfoComparator());
				linkSignatures(signatures);

				for (PdfSignatureOrDocTimestampInfo sig : signatures) {
					logger.debug("Signature " + sig.uniqueId() + " found with byteRange " + Arrays.toString(sig.getSignatureByteRange()) + " (" + sig.getSubFilter() + ")");
				}
			}

		} catch (Exception e) {
			logger.warn("Cannot analyze signatures : " + e.getMessage(), e);
		} finally {
			DSSUtils.closeQuietly(bais);
			DSSUtils.closeQuietly(doc);
		}

		return signatures;
	}

	/**
	 * This method links previous signatures to the new one. This is useful to get revision number and to know if a TSP is over the DSS dictionary
	 */
	private void linkSignatures(List<PdfSignatureOrDocTimestampInfo> signatures) {
		List<PdfSignatureOrDocTimestampInfo> previousList = new ArrayList<PdfSignatureOrDocTimestampInfo>();
		for (PdfSignatureOrDocTimestampInfo sig : signatures) {
			if (DSSUtils.isNotEmpty(previousList)) {
				for (PdfSignatureOrDocTimestampInfo previous : previousList) {
					previous.addOuterSignature(sig);
				}
			}
			previousList.add(sig);
		}
	}


	private boolean isDSSDictionaryPresentInPreviousRevision(byte[] originalBytes) {
		ByteArrayInputStream bais = null;
		PDDocument doc = null;
		PdfDssDict dssDictionary = null;
		try {
			bais = new ByteArrayInputStream(originalBytes);
			doc = PDDocument.load(bais);
			List<PDSignature> pdSignatures = doc.getSignatureDictionaries();
			if (DSSUtils.isNotEmpty(pdSignatures)) {
				PdfDict catalog = new PdfBoxDict(doc.getDocumentCatalog().getCOSDictionary(), doc);
				dssDictionary = PdfDssDict.build(catalog);
			}
		} catch (Exception e) {
			logger.warn("Cannot check in previous revisions if DSS dictionary already exist : " + e.getMessage(), e);
		} finally {
			DSSUtils.closeQuietly(bais);
			DSSUtils.closeQuietly(doc);
		}

		return dssDictionary != null;
	}

	private byte[] getOriginalBytes(int[] byteRange, byte[] signedContent) {
		final int length = byteRange[1];
		final byte[] result = new byte[length];
		System.arraycopy(signedContent, 0, result, 0, length);
		return result;
	}

	@Override
	public void addDssDictionary(InputStream inputStream, OutputStream outputStream, ModelPdfDict dssDictionary) {
		FileInputStream fis = null;
		PDDocument pdDocument = null;
		try {

			File toSignFile = DSSPDFUtils.getFileFromPdfData(inputStream);

			pdDocument = PDDocument.load(toSignFile);

			File signedFile = File.createTempFile("sd-dss-", "-signed.pdf");

			final FileOutputStream fileOutputStream = DSSPDFUtils.getFileOutputStream(toSignFile, signedFile);

			if (dssDictionary != null) {
				final COSDictionary cosDictionary = pdDocument.getDocumentCatalog().getCOSDictionary();
				PdfBoxDict value = new PdfBoxDict(dssDictionary);
				cosDictionary.setItem("DSS", value.getWrapped());
				cosDictionary.setNeedToBeUpdate(true);
			}

			if (pdDocument.getDocumentId() == null) {
				pdDocument.setDocumentId(0L);
			}
			pdDocument.saveIncremental(inputStream, fileOutputStream);

			fis = new FileInputStream(signedFile);
			IOUtils.copy(fis, outputStream);
		} catch (Exception e) {
			throw new DSSException(e);
		} finally {
			DSSUtils.closeQuietly(pdDocument);
			DSSUtils.closeQuietly(fis);
		}
	}

}