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

package eu.europa.ec.markt.dss.signature.xades;

import java.util.List;

import org.apache.xml.security.Init;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.AbstractSignatureService;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.ProfileParameters;
import eu.europa.ec.markt.dss.signature.ProfileParameters.Operation;
import eu.europa.ec.markt.dss.signature.SignatureExtension;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.token.DSSPrivateKeyEntry;
import eu.europa.ec.markt.dss.signature.token.SignatureTokenConnection;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;

/**
 * XAdES implementation of DocumentSignatureService
 *
 * @author Robert Bielecki
 */
public class XAdESService extends AbstractSignatureService {

	private static final Logger LOG = LoggerFactory.getLogger(XAdESService.class);

	static {

		Init.init();
	}

	/**
	 * This is the constructor to create an instance of the {@code XAdESService}. A certificate verifier must be provided.
	 *
	 * @param certificateVerifier {@code CertificateVerifier} provides information on the sources to be used in the validation process in the context of a signature.
	 */
	public XAdESService(final CertificateVerifier certificateVerifier) {

		super(certificateVerifier);
		LOG.debug("+ XAdESService created");
	}

	@Override
	public byte[] getDataToSign(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		assertSigningDateInCertificateValidityRange(parameters);

		final XAdESLevelBaselineB levelBaselineB = new XAdESLevelBaselineB(cryptographicSourceProvider);
		final byte[] dataToSign = levelBaselineB.getDataToSign(toSignDocument, parameters);
		parameters.getContext().setProfile(levelBaselineB);
		return dataToSign;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters, final byte[] signatureValue) throws DSSException {

		if (toSignDocument == null) {
			throw new DSSNullException(DSSDocument.class);
		}
		if (parameters == null) {
			throw new DSSNullException(SignatureParameters.class);
		}
		if (parameters.getSignatureLevel() == null) {
			throw new DSSNullException(SignatureLevel.class);
		}
		if (signatureValue == null) {
			throw new DSSNullException(byte[].class, "signatureValue");
		}
		assertSigningDateInCertificateValidityRange(parameters);
		parameters.getContext().setOperationKind(Operation.SIGNING);
		final ProfileParameters context = parameters.getContext();
		final XAdESLevelBaselineB profile = context.getProfile() != null ? context.getProfile() : new XAdESLevelBaselineB(cryptographicSourceProvider);
		final DSSDocument signedDoc = profile.signDocument(toSignDocument, parameters, signatureValue);
		final SignatureExtension extension = getExtensionProfile(parameters);
		if (extension != null) {

			if (SignaturePackaging.DETACHED.equals(parameters.getSignaturePackaging())) {

				parameters.setDetachedContent(toSignDocument);
			}
			final DSSDocument dssExtendedDocument = extension.extendSignatures(signedDoc, parameters);
			// The deterministic id is reset between two consecutive signing operations. It prevents having two signatures with the same Id within the same document.
			parameters.setDeterministicId(null);
			return dssExtendedDocument;
		}
		parameters.setDeterministicId(null);
		return signedDoc;
	}

	@Override
	public DSSDocument signDocument(final DSSDocument toSignDocument, final SignatureParameters parameters) throws DSSException {

		if (parameters.getSignatureLevel() == null) {
			throw new DSSNullException(SignatureLevel.class);
		}
		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {
			throw new DSSNullException(SignatureTokenConnection.class);
		}

		parameters.getContext().setOperationKind(Operation.SIGNING);

		final XAdESLevelBaselineB profile = new XAdESLevelBaselineB(cryptographicSourceProvider);
		final byte[] dataToSign = profile.getDataToSign(toSignDocument, parameters);
		parameters.getContext().setProfile(profile);

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getPrivateKeyEntry();
		final byte[] signatureValue = signingToken.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);
		final DSSDocument dssDocument = signDocument(toSignDocument, parameters, signatureValue);
		return dssDocument;
	}

	@Override
	public DSSDocument extendDocument(final DSSDocument toExtendDocument, final SignatureParameters parameters) throws DSSException {

		parameters.getContext().setOperationKind(Operation.EXTENDING);
		final SignatureExtension extension = getExtensionProfile(parameters);
		if (extension != null) {

			final DSSDocument dssDocument = extension.extendSignatures(toExtendDocument, parameters);
			return dssDocument;
		}
		throw new DSSException("Cannot extend to " + parameters.getSignatureLevel().name());
	}

	public DSSDocument counterSign(final DSSDocument toCounterSignature, final SignatureParameters parameters) throws DSSException {

		if (toCounterSignature == null) {
			throw new DSSNullException(DSSDocument.class, "toCounterSignature");
		}
		if (parameters == null) {
			throw new DSSNullException(SignatureParameters.class);
		}
		if (parameters.getSignatureLevel() == null) {
			throw new DSSNullException(SignatureLevel.class);
		}
		final SignatureTokenConnection signingToken = parameters.getSigningToken();
		if (signingToken == null) {
			throw new DSSNullException(SignatureTokenConnection.class);
		}
		final String toCounterSignSignatureId = parameters.getToCounterSignSignatureId();
		if (DSSUtils.isBlank(toCounterSignSignatureId)) {
			throw new DSSException("There is no provided signature id to countersign!");
		}
		final XAdESSignature xadesSignature = getToCountersignSignature(toCounterSignature, toCounterSignSignatureId);
		if (xadesSignature == null) {
			throw new DSSException("The signature to countersign not found!");
		}
		final Node signatureValueNode = xadesSignature.getSignatureValue();
		if (signatureValueNode == null) {
			throw new DSSNullException(Node.class, "signature-value");
		}
		final String signatureValueId = DSSXMLUtils.getIDIdentifier((Element) signatureValueNode);
		if (DSSUtils.isBlank(toCounterSignSignatureId)) {
			throw new DSSException("There is no signature-value id to countersign!");
		}
		parameters.setToCounterSignSignatureValueId(signatureValueId);

		final CounterSignatureBuilder counterSignatureBuilder = new CounterSignatureBuilder(toCounterSignature, xadesSignature, parameters, cryptographicSourceProvider);
		final byte[] dataToSign = counterSignatureBuilder.build();

		final DigestAlgorithm digestAlgorithm = parameters.getDigestAlgorithm();
		final DSSPrivateKeyEntry dssPrivateKeyEntry = parameters.getPrivateKeyEntry();

		byte[] counterSignatureValue = signingToken.sign(dataToSign, digestAlgorithm, dssPrivateKeyEntry);

		final DSSDocument counterSignedDocument = counterSignatureBuilder.signDocument(counterSignatureValue);
		//		final XMLDocumentValidator xmlDocumentValidator = (XMLDocumentValidator) validator;
		//		final Document rootElement = xmlDocumentValidator.getRootElement();
		//		final byte[] bytes = DSSXMLUtils.transformDomToByteArray(rootElement);
		//		final InMemoryDocument inMemoryDocument = new InMemoryDocument(bytes);
		return counterSignedDocument;
	}

	private XAdESSignature getToCountersignSignature(final DSSDocument toCounterSignature, final String toCounterSignSignatureId) {

		final SignedDocumentValidator validator = SignedDocumentValidator.fromDocument(toCounterSignature);
		if (!(validator instanceof XMLDocumentValidator)) {
			throw new DSSException("Incompatible signature form!");
		}
		final List<AdvancedSignature> advancedSignatureList = validator.getSignatures();
		XAdESSignature xadesSignature = null;
		for (final AdvancedSignature advancedSignature : advancedSignatureList) {

			final String id = advancedSignature.getId();
			if (toCounterSignSignatureId.equals(id)) {

				xadesSignature = (XAdESSignature) advancedSignature;
				break;
			}
		}
		return xadesSignature;
	}

	/**
	 * The choice of profile according to the passed parameter.
	 *
	 * @param parameters
	 * @return
	 */
	private SignatureExtension getExtensionProfile(final SignatureParameters parameters) {

		switch (parameters.getSignatureLevel()) {
			case XAdES_BASELINE_B:

				return null;
			case XAdES_BASELINE_T:

				final XAdESLevelBaselineT extensionT = new XAdESLevelBaselineT(parameters, cryptographicSourceProvider);
				extensionT.setTspSource(tspSource);
				return extensionT;
			case XAdES_C:

				final XAdESLevelC extensionC = new XAdESLevelC(parameters, cryptographicSourceProvider);
				extensionC.setTspSource(tspSource);
				return extensionC;
			case XAdES_X:

				final XAdESLevelX extensionX = new XAdESLevelX(parameters, cryptographicSourceProvider);
				extensionX.setTspSource(tspSource);
				return extensionX;
			case XAdES_XL:

				final XAdESLevelXL extensionXL = new XAdESLevelXL(parameters, cryptographicSourceProvider);
				extensionXL.setTspSource(tspSource);
				return extensionXL;
			case XAdES_A:

				final XAdESLevelA extensionA = new XAdESLevelA(parameters, cryptographicSourceProvider);
				extensionA.setTspSource(tspSource);
				return extensionA;
			case XAdES_BASELINE_LT:

				final XAdESLevelBaselineLT extensionLT = new XAdESLevelBaselineLT(parameters, cryptographicSourceProvider);
				extensionLT.setTspSource(tspSource);
				return extensionLT;
			case XAdES_BASELINE_LTA:

				final XAdESLevelBaselineLTA extensionLTA = new XAdESLevelBaselineLTA(parameters, cryptographicSourceProvider);
				extensionLTA.setTspSource(tspSource);
				return extensionLTA;
			default:
				throw new DSSException("Unsupported signature format: '" + parameters.getSignatureLevel() + "'!");
		}
	}
}
