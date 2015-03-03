/*
 * SD-DSS - Digital Signature Services
 *
 * Copyright (C) 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * Developed by: 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * This file is part of the "https://github.com/arhs/sd-dss" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "SD-DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.signature.cades;

import java.io.InputStream;

import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInfoGeneratorBuilder;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;

/**
 * CAdES implementation of DocumentSignatureService
 *
 * @author Robert Bielecki
 */

public class CAdESService extends AbstractSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(CAdESService.class);

	private final CMSSignedDataBuilder cmsSignedDataBuilder;

	/**
	 * This is the constructor to create an instance of the {@code CAdESService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public CAdESService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		cmsSignedDataBuilder = new CMSSignedDataBuilder(certificateVerifier);
		LOG.debug("+ CAdESService created");
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		assertSignaturePackaging(packaging);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId());
		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, false);
		final CMSSignedData originalCmsSignedData = getCmsSignedData(toSignDocument, parameters);

		final CMSSignedDataGenerator cmsSignedDataGenerator = cmsSignedDataBuilder
			  .createCMSSignedDataGenerator(parameters, customContentSigner, signerInfoGeneratorBuilder, originalCmsSignedData);

		final DSSDocument toSignData = getToSignData(toSignDocument, parameters, originalCmsSignedData);

		final CMSProcessableByteArray content = new CMSProcessableByteArray(toSignData.getBytes());
		final boolean encapsulate = !SignaturePackaging.DETACHED.equals(packaging);
		DSSASN1Utils.generateCMSSignedData(cmsSignedDataGenerator, content, encapsulate);
		final byte[] bytes = customContentSigner.getOutputStream().toByteArray();
		return bytes;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);
		final SignaturePackaging packaging = parameters.getSignaturePackaging();
		assertSignaturePackaging(packaging);

		final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
		final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue);
		final SignerInfoGeneratorBuilder signerInfoGeneratorBuilder = cmsSignedDataBuilder.getSignerInfoGeneratorBuilder(parameters, true);
		final CMSSignedData originalCmsSignedData = getCmsSignedData(toSignDocument, parameters);
		if (originalCmsSignedData == null && SignaturePackaging.DETACHED.equals(packaging) && parameters.getDetachedContent() == null) {

			parameters.setDetachedContent(toSignDocument);
		}

		final CMSSignedDataGenerator cmsSignedDataGenerator = cmsSignedDataBuilder
			  .createCMSSignedDataGenerator(parameters, customContentSigner, signerInfoGeneratorBuilder, originalCmsSignedData);

		final DSSDocument toSignData = getToSignData(toSignDocument, parameters, originalCmsSignedData);
		final CMSProcessableByteArray content = new CMSProcessableByteArray(toSignData.getBytes());
		final boolean encapsulate = !SignaturePackaging.DETACHED.equals(packaging);
		final CMSSignedData cmsSignedData = DSSASN1Utils.generateCMSSignedData(cmsSignedDataGenerator, content, encapsulate);
		final CMSSignedDocument signature = new CMSSignedDocument(cmsSignedData);

		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		if (!SignatureLevel.CAdES_BASELINE_B.equals(signatureLevel)) {

			// true: Only the last signature will be extended
			final SignatureExtension extension = getExtensionProfile(parameters, true);
			final DSSDocument extendSignature = extension.extendSignatures(signature, parameters);
			parameters.setDeterministicId(null);
			return extendSignature;
		}
		parameters.setDeterministicId(null);
		return signature;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		final SignatureTokenConnection token = parameters.getSigningToken();
		if (token == null) {

			throw new DSSNullException(SignatureTokenConnection.class, "", "The connection through available API to the SSCD must be set.");
		}
		final byte[] dataToSign = getDataToSign(toSignDocument, parameters);
		byte[] signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), parameters.getPrivateKeyEntry());
		final DSSDocument document = signDocument(toSignDocument, parameters, signatureValue);
		return document;
	}

	/**
	 * This method countersigns a signature identified through its SignerId
	 *
	 * @param toCounterSignDocument the original signature document containing the signature to countersign
	 * @param parameters            the signature parameters
	 * @param selector              the SignerId identifying the signature to countersign
	 * @return the updated signature document, in which the countersignature has been embedded
	 */
	public DSSDocument counterSignDocument(final DSSDocument toCounterSignDocument, final SignatureParameters parameters, SignerId selector) {

		final SignatureTokenConnection token = parameters.getSigningToken();
		if (token == null) {

			throw new DSSNullException(SignatureTokenConnection.class, "", "The connection through available API to the SSCD must be set.");
		}

		try {
			//Retrieve the original signature
			final InputStream inputStream = toCounterSignDocument.openStream();
			final CMSSignedData cmsSignedData = new CMSSignedData(inputStream);
			DSSUtils.closeQuietly(inputStream);

			SignerInformationStore signerInfos = cmsSignedData.getSignerInfos();
			SignerInformation signerInformation = signerInfos.get(selector);

			//Generate a signed digest on the contents octets of the signature octet String in the identified SignerInfo value
			//of the original signature's SignedData
			byte[] dataToSign = signerInformation.getSignature();
			byte[] signatureValue = token.sign(dataToSign, parameters.getDigestAlgorithm(), parameters.getPrivateKeyEntry());

			//Set the countersignature builder
			CounterSignatureBuilder builder = new CounterSignatureBuilder(cryptographicSourceProvider);
			builder.setCmsSignedData(cmsSignedData);
			builder.setSelector(selector);

			final SignatureAlgorithm signatureAlgorithm = parameters.getSignatureAlgorithm();
			final CustomContentSigner customContentSigner = new CustomContentSigner(signatureAlgorithm.getJCEId(), signatureValue);

			SignerInfoGeneratorBuilder signerInformationGeneratorBuilder = builder.getSignerInfoGeneratorBuilder(parameters, true);
			CMSSignedDataGenerator cmsSignedDataGenerator = builder.createCMSSignedDataGenerator(parameters, customContentSigner, signerInformationGeneratorBuilder, null);
			CMSTypedData content = cmsSignedData.getSignedContent();
			CMSSignedData signedData = cmsSignedDataGenerator.generate(content);
			final CMSSignedData countersignedCMSData = builder.signDocument(signedData);
			final CMSSignedDocument signature = new CMSSignedDocument(countersignedCMSData);
			return signature;

		} catch (CMSException e) {
			throw new DSSException("Cannot parse CMS data", e);
		}
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final SignatureParameters parameters) {

		// false: All signature are extended
		final SignatureExtension extension = getExtensionProfile(parameters, false);
		final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
		return dssDocument;
	}

	/**
	 * This method retrieves the data to be signed. It this data is located within a signature then it is extracted.
	 *
	 * @param toSignDocument        document to sign
	 * @param parameters            set of the driving signing parameters
	 * @param originalCmsSignedData the signed data extracted from an existing signature or null
	 * @return
	 */
	private DSSDocument getToSignData(final DSSDocument toSignDocument, final SignatureParameters parameters, final CMSSignedData originalCmsSignedData) {

		final DSSDocument detachedContent = parameters.getDetachedContent();
		if (detachedContent != null) {

			return detachedContent;
		} else {

			if (originalCmsSignedData == null) {
				return toSignDocument;
			} else {
				return getSignedContent(originalCmsSignedData);
			}
		}
	}

	/**
	 * This method returns the signed content of CMSSignedData.
	 *
	 * @param cmsSignedData the already signed {@code CMSSignedData}
	 * @return the original toSignDocument or null
	 */
	private DSSDocument getSignedContent(final CMSSignedData cmsSignedData) {

		if (cmsSignedData != null) {

			final CMSTypedData signedContent = cmsSignedData.getSignedContent();
			final byte[] documentBytes = (signedContent != null) ? (byte[]) signedContent.getContent() : null;
			final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
			return inMemoryDocument;
		}
		return null;
	}

	/**
	 * @param parameters           set of driving signing parameters
	 * @param onlyLastCMSSignature indicates if only the last CSM signature should be extended
	 * @return {@code SignatureExtension} related to the predefine profile
	 */
	private SignatureExtension getExtensionProfile(final SignatureParameters parameters, final boolean onlyLastCMSSignature) {

		final SignatureLevel signatureLevel = parameters.getSignatureLevel();
		switch (signatureLevel) {
			case CAdES_BASELINE_T:
				return new CAdESLevelBaselineT(tspSource, cryptographicSourceProvider, onlyLastCMSSignature);
			case CAdES_BASELINE_LT:
				return new CAdESLevelBaselineLT(tspSource, cryptographicSourceProvider, onlyLastCMSSignature);
			case CAdES_BASELINE_LTA:
				return new CAdESLevelBaselineLTA(tspSource, cryptographicSourceProvider, onlyLastCMSSignature);
			default:
				throw new DSSException("Unsupported signature format " + signatureLevel);
		}
	}

	/**
	 * In case of an enveloping signature if the signed content's content is null then the null is returned.
	 *
	 * @param dssDocument {@code DSSDocument} containing the data to be signed or {@code CMSSignedData}
	 * @param parameters  set of driving signing parameters
	 * @return the {@code CMSSignedData} if the dssDocument is an CMS signed message. Null otherwise.
	 */
	private CMSSignedData getCmsSignedData(final DSSDocument dssDocument, final SignatureParameters parameters) {

		CMSSignedData cmsSignedData = null;
		try {
			// check if input dssDocument is already signed
			cmsSignedData = new CMSSignedData(dssDocument.getBytes());
			final SignaturePackaging signaturePackaging = parameters.getSignaturePackaging();
			if (signaturePackaging == SignaturePackaging.ENVELOPING) {

				if (cmsSignedData.getSignedContent().getContent() == null) {
					cmsSignedData = null;
				}
			}
		} catch (Exception e) {
			// not a parallel signature
		}
		return cmsSignedData;
	}

	/**
	 * @param packaging {@code SignaturePackaging} to be checked
	 * @throws DSSException if the packaging is not supported for this kind of signature
	 */
	private void assertSignaturePackaging(final SignaturePackaging packaging) throws DSSException {

		if (packaging != SignaturePackaging.ENVELOPING && packaging != SignaturePackaging.DETACHED) {
			throw new DSSException("Unsupported signature packaging: " + packaging);
		}
	}
}
