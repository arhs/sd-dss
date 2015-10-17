/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2014 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2014 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.signature.timestamp;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignatureException;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.parameter.TimestampParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.SignatureLevel;
import eu.europa.ec.markt.dss.signature.SignaturePackaging;
import eu.europa.ec.markt.dss.signature.xades.XAdESLevelBaselineB;
import eu.europa.ec.markt.dss.validation102853.AdvancedSignature;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CryptographicSourceProvider;
import eu.europa.ec.markt.dss.validation102853.SignedDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.TimestampInclude;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;
import eu.europa.ec.markt.dss.validation102853.xades.XAdESSignature;
import eu.europa.ec.markt.dss.validation102853.xades.XMLDocumentValidator;
import eu.europa.ec.markt.dss.validation102853.xades.XPathQueryHolder;

import static eu.europa.ec.markt.dss.validation102853.TimestampType.ALL_DATA_OBJECTS_TIMESTAMP;
import static eu.europa.ec.markt.dss.validation102853.TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP;

/**
 * Class providing (content) timestamp generating methods
 */
public class TimestampService {

	private static final Logger LOG = LoggerFactory.getLogger(TimestampService.class);

	private final TSPSource tspSource;
	private final CertificatePool certificatePool;
	private final XPathQueryHolder xPathQueryHolder;
	private final CryptographicSourceProvider cryptographicSourceProvider = new CryptographicSourceProvider(true);


	// TODO (12/09/2014): To be replaced for the new release (4.2.0)
	private final String fakeSignatureValue128 = "kKk8sPvKC4RN1/W8Uqan2zgqNCH2Uh6I4/uQPha25W6Lz6poWuxmi9y8/iCR2anbFb1k4n3d0eJxzWzdD4ubz478it9J0jhFi/4ANFJG+FVrWqH9gw/nXnfy2nULQOY466HE172mIAjKjWdPrpo6z1IRWHYbzNbL4iSO8BxqMx0=";
	private final String fakeSignatureValue256 = "ckWishp0GDDzSsPjYnTDrYhSQYc6afe4uyKYLLvNvJvp/Q9PR1cPs0+g24G1JFGYbt4wotxueUaJp2kCP+6iNCxQmc9wqLnyRQqgGw8I6002/qx9WFa9FB9WpGPItWfU42Zru/C0OpXkXrAddkpPVU7nLxUMEsC2emYAsKL0k8+M/B1vJa2ifbuycnzYqZZsaxPkBkGaf1kt3aLA5a6iAPY1w/TVC50abhzsTJ2OEwGt2PiIZWQyWHr42W5NcDLqXdASLMWoIWFF24e2Ih6zsosvMho9MoKSC+NRFI+H7Z6v2QIN+8+3+vE/4CKggbmNUWepAmsEMudLi4+vYcHKFw==";

	/**
	 * Basic constructor, new CertificatePool created
	 *
	 * @param tspSource The TSPSource to be used for the Timestamp generation
	 */
	public TimestampService(final TSPSource tspSource) {
		if (tspSource == null) {
			throw new DSSNullException(TSPSource.class);
		}
		this.tspSource = tspSource;
		certificatePool = new CertificatePool();
		xPathQueryHolder = new XPathQueryHolder();
	}


	/**
	 * Alternative constructor
	 *
	 * @param tspSource       The TSPSource to be used for the Timestamp generation
	 * @param certificatePool The CertificatePool to be used for the TimestampToken
	 */
	public TimestampService(final TSPSource tspSource, final CertificatePool certificatePool) {

		if (tspSource == null) {
			throw new DSSNullException(TSPSource.class);
		}
		this.tspSource = tspSource;

		if (certificatePool == null) {
			throw new DSSNullException(CertificatePool.class);
		}
		this.certificatePool = certificatePool;
		xPathQueryHolder = new XPathQueryHolder();
	}

	/**
	 * Method that generates a ContentTimestamp as a DSSDocument
	 *
	 * @param externalParameters the original signature parameters
	 * @return contentTimestamp as an InMemoryDocument
	 */
	public DSSDocument generateCAdESContentTimestamp(final SignatureParameters externalParameters) {

		final TimestampToken contentTimestampToken = generateCAdESContentTimestampAsTimestampToken(externalParameters);
		final InMemoryDocument document = new InMemoryDocument(contentTimestampToken.getEncoded());

		return document;
	}

	/**
	 * Method that generates a ContentTimestamp as a DSS TimestampToken
	 * *
	 *
	 * @param externalParameters the original signature parameters
	 * @return the ContentTimestamp as a DSS TimestampToken
	 */
	public TimestampToken generateCAdESContentTimestampAsTimestampToken(final SignatureParameters externalParameters) {

		final byte[] bytes = externalParameters.getDetachedContent().getBytes();
		final TimestampToken token = generateTimestampToken(TimestampType.CONTENT_TIMESTAMP, externalParameters, bytes);
		return token;
	}

	/**
	 * Method that generates a XAdES ContentTimestamp (either an ALL DATA OBJECTS TIMESTAMP or an INDIVIDUAL DATA OBJECTS TIMESTAMP) and returns
	 * it as a TimestampToken
	 *
	 * @param toSignDocument
	 * @param externalParameters
	 * @param timestampType
	 * @return
	 */
	public TimestampToken generateXAdESContentTimestampAsTimestampToken(final DSSDocument toSignDocument, final SignatureParameters externalParameters,
	                                                                    final TimestampType timestampType) {

		if (externalParameters == null) {
			throw new DSSNullException(SignatureParameters.class);
		}
		if (timestampType != ALL_DATA_OBJECTS_TIMESTAMP && timestampType != INDIVIDUAL_DATA_OBJECTS_TIMESTAMP) {
			throw new DSSException("Incompatible timestamp type");
		}

		//1. Set initial parameters
		final SignatureParameters timestampParameters = getTimestampParameters(externalParameters);

		//2. Build temporary signature structure
		final XAdESLevelBaselineB levelBaselineB = new XAdESLevelBaselineB(cryptographicSourceProvider);

		byte[] signatureValueBytes = DSSUtils.base64Decode(fakeSignatureValue256);
		final DSSDocument fullSignature = levelBaselineB.signDocument(toSignDocument, timestampParameters, signatureValueBytes);
		fullSignature.save("c:/temp/sign.xml");
		final List<Reference> references = getReferencesFromValidatedSignature(toSignDocument, fullSignature);

		//4. Concatenate byte value of references, excluding references of type SignedProperties
		byte[] concatenatedReferences = concatenateReferencesAsByteArray(references);

		//5. Generate ContentTimestamp using the concatenated references
		return generateTimestampToken(timestampType, externalParameters, concatenatedReferences);
	}

	/**
	 * Concatenates a set of given {@code Reference} into a byte array
	 *
	 * @param references the references to concatenate
	 * @return the concatenated references as a byte array
	 */
	private byte[] concatenateReferencesAsByteArray(final List<Reference> references) {

		LOG.debug("Building ContentTimestamp - Concatenating references...");
		final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

		for (final Reference reference : references) {
			//References of type "SignedProperties" are excluded
			if (!xPathQueryHolder.XADES_SIGNED_PROPERTIES.equals(reference.getType())) {
				try {
					final byte[] referencedBytes = reference.getReferencedBytes();
					buffer.write(referencedBytes);
				} catch (XMLSignatureException e) {
					throw new DSSException(e);
				} catch (IOException e) {
					throw new DSSException(e);
				}
			}
		}
		LOG.debug("Result: " + new String(buffer.toByteArray()));
		return buffer.toByteArray();
	}

	/**
	 * Method that generates a XAdES ContentTimestamp (either an ALL DATA OBJECTS TIMESTAMP or an INDIVIDUAL DATA OBJECTS TIMESTAMP) and returns
	 * it as a DSSDocument
	 *
	 * @param toSignDocument     the document for which a content timestamp must be generated
	 * @param externalParameters the original signature parameters
	 * @param timestampType      the contentTimestamp type, either ALL_DATA_OBJECTS_TIMESTAMP or INDIVIDUAL_DATA_OBJECTS_TIMESTAMP
	 * @return a ContentTimestamp as a DSSDocument
	 */
	public DSSDocument generateXAdESContentTimestampAsDSSDocument(final DSSDocument toSignDocument, final SignatureParameters externalParameters,
	                                                              final TimestampType timestampType) {
		final TimestampToken timestampToken = generateXAdESContentTimestampAsTimestampToken(toSignDocument, externalParameters, timestampType);
		return new InMemoryDocument(timestampToken.getEncoded());
	}

	/**
	 * Method that generates a TimestampToken given a TimestampType, a set of signature parameters and a byte array containing the concatenated references
	 *
	 * @param timestampType       The TimestampType for the TimestampToken
	 * @param signatureParameters The signature parameters from which the contentTimestamp parameters must be retrieved
	 * @param references
	 * @return
	 */
	public TimestampToken generateTimestampToken(final TimestampType timestampType, final SignatureParameters signatureParameters, final byte[] references) {

		if (timestampType == null) {
			throw new DSSNullException(TimestampType.class);
		}
		if (signatureParameters == null) {
			throw new DSSNullException(SignatureParameters.class);
		}
		final TimestampParameters contentTimestampParameters = signatureParameters.getContentTimestampParameters();
		if (contentTimestampParameters == null) {
			throw new DSSNullException(TimestampParameters.class);
		}

		final DigestAlgorithm digestAlgorithm = contentTimestampParameters.getDigestAlgorithm();
		if (digestAlgorithm == null) {
			throw new DSSNullException(DigestAlgorithm.class);
		}
		byte[] digest = DSSUtils.digest(digestAlgorithm, references);
		if (LOG.isTraceEnabled()) {

			LOG.trace("Bytes to digest : [" + DSSUtils.base64Encode(references) + "]");
			LOG.trace("Digest to timestamp: " + DSSUtils.base64Encode(digest));
		}
		final TimeStampToken timeStampResponse = tspSource.getTimeStampResponse(digestAlgorithm, digest);
		final TimestampToken token = new TimestampToken(timeStampResponse, timestampType, certificatePool);

		token.setCanonicalizationMethod(contentTimestampParameters.getCanonicalizationMethod());

		//Case of XAdES INDIVIDUAL DATA OBJECTS TIMESTAMP: Timestamp Includes must be generated for each reference
		if (INDIVIDUAL_DATA_OBJECTS_TIMESTAMP.equals(timestampType)) {
			addTimestampTokenIncludes(signatureParameters.getReferences(), token);
		}
		return token;
	}

	/**
	 * Method setting the signature parameters used to generate the intermediary signature (XAdES-specific)
	 *
	 * @param signatureParameters the original signature parameters
	 * @return a set of signature parameters
	 */
	private SignatureParameters getTimestampParameters(final SignatureParameters signatureParameters) {

		final SignatureParameters timestampParameters = new SignatureParameters();
		timestampParameters.setReferences(signatureParameters.getReferences());
		timestampParameters.setSignatureTimestampParameters(signatureParameters.getSignatureTimestampParameters());
		timestampParameters.setSigningCertificate(signatureParameters.getSigningCertificate());
		timestampParameters.setSignaturePackaging(SignaturePackaging.DETACHED);
		timestampParameters.setSignatureLevel(SignatureLevel.XAdES_BASELINE_B);

		return timestampParameters;
	}

	/**
	 * Retrieves the references from a validated signature
	 *
	 * @param toSignDocument the document for which a content timestamp must be generated
	 * @param signature      the signature value
	 * @return
	 */
	private List<Reference> getReferencesFromValidatedSignature(final DSSDocument toSignDocument, final DSSDocument signature) {

		final SignedDocumentValidator validator = validateTemporarySignature(toSignDocument, signature);
		final List<AdvancedSignature> signatures = validator.getSignatures();
		final XAdESSignature xadesSignature = (XAdESSignature) signatures.get(0);
		xadesSignature.checkSignatureIntegrity();
		final List<Reference> references = xadesSignature.getReferences();

		return references;
	}

	/**
	 * @param toSignDocument
	 * @param signature
	 * @return
	 */
	private SignedDocumentValidator validateTemporarySignature(final DSSDocument toSignDocument, final DSSDocument signature) {

		final SignedDocumentValidator validator = XMLDocumentValidator.fromDocument(signature);
		validator.setCertificateVerifier(cryptographicSourceProvider);
		final List<DSSDocument> detachedContents = new ArrayList<DSSDocument>();
		detachedContents.add(toSignDocument);
		validator.setDetachedContents(detachedContents);

		return validator;
	}

	/**
	 * Adds a set of Timestamp Includes to a given Timestamp Token, based on the references that the Timestamp Token was built upon
	 *
	 * @param references the references the timestamp token was built upon
	 * @param token      the timestamp token to which the includes must be added
	 * @return the updated Timestamp token, containing the set of Includes
	 */
	private TimestampToken addTimestampTokenIncludes(final List<DSSReference> references, final TimestampToken token) {

		final List<TimestampInclude> includes = new ArrayList<TimestampInclude>();
		for (final DSSReference reference : references) {

			final TimestampInclude include = new TimestampInclude(reference.getId(), "true");
			includes.add(include);
		}
		token.setTimestampIncludes(includes);
		return token;
	}
}
