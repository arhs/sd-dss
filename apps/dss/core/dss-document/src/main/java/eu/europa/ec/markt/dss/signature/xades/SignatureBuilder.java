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

package eu.europa.ec.markt.dss.signature.xades;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.datatype.XMLGregorianCalendar;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.EncryptionAlgorithm;
import eu.europa.ec.markt.dss.SignatureAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.parameter.ChainCertificate;
import eu.europa.ec.markt.dss.parameter.DSSReference;
import eu.europa.ec.markt.dss.parameter.DSSTransform;
import eu.europa.ec.markt.dss.parameter.SignatureParameters;
import eu.europa.ec.markt.dss.signature.BLevelParameters;
import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.DSSSignatureUtils;
import eu.europa.ec.markt.dss.signature.InMemoryDocument;
import eu.europa.ec.markt.dss.signature.MimeType;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateVerifier;
import eu.europa.ec.markt.dss.validation102853.TimestampInclude;
import eu.europa.ec.markt.dss.validation102853.TimestampToken;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.tsp.TSPSource;

import static eu.europa.ec.markt.dss.XAdESNamespaces.XAdES;
import static eu.europa.ec.markt.dss.validation102853.TimestampType.ALL_DATA_OBJECTS_TIMESTAMP;
import static eu.europa.ec.markt.dss.validation102853.TimestampType.INDIVIDUAL_DATA_OBJECTS_TIMESTAMP;
import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

/**
 * This class implements all the necessary mechanisms to build each form of the XML signature.
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 672 $ - $Date: 2011-05-12 11:59:21 +0200 (Thu, 12 May 2011) $
 */
public abstract class SignatureBuilder extends XAdESBuilder {

	/**
	 * Indicates if the signature was already built. (Two steps building)
	 */
	protected boolean built = false;

	/**
	 * This is the reference to the original document to sign
	 */
	protected DSSDocument detachedDocument;

	protected String signedInfoCanonicalizationMethod;
	protected String signedPropertiesCanonicalizationMethod;

	protected String deterministicId;

	/*
	 * This variable represents the current DOM signature object.
	 */
	protected Element signatureDom;

	protected Element signedInfoDom;
	protected Element signatureValueDom;
	protected Element qualifyingPropertiesDom;
	protected Element signedPropertiesDom;
	protected Element signedSignaturePropertiesDom;
	protected Element signedDataObjectPropertiesDom;
	protected Element unsignedSignaturePropertiesDom;

	/*
	 * The object encapsulating the Time Stamp Protocol needed to create the level -T, of the signature
     */
	protected TSPSource tspSource;

	/**
	 * The default constructor for SignatureBuilder.
	 *
	 * @param params              {@code SignatureParameters} representing the set of parameters relating to the structure and process of the creation or extension of the
	 *                            electronic signature.
	 * @param detachedDocument    {@code DSSDocument} representing the original document to sign.
	 * @param certificateVerifier {@code CryptographicSourceProvider}
	 */
	protected SignatureBuilder(final SignatureParameters params, final DSSDocument detachedDocument, final CertificateVerifier certificateVerifier) {

		super(params, certificateVerifier);
		this.detachedDocument = detachedDocument;
	}

	/**
	 * Creates the signature according to the packaging
	 *
	 * @param params              {@code SignatureParameters} representing the set of parameters relating to the structure and process of the creation or extension of the
	 *                            electronic signature.
	 * @param document            {@code DSSDocument} representing the original document to sign.
	 * @param certificateVerifier {@code CryptographicSourceProvider}
	 * @return {@code SignatureBuilder}  created according to the packaging
	 */
	public static SignatureBuilder getSignatureBuilder(final SignatureParameters params, final DSSDocument document, final CertificateVerifier certificateVerifier) {

		switch (params.getSignaturePackaging()) {
			case ENVELOPED:
				return new EnvelopedSignatureBuilder(params, document, certificateVerifier);
			case ENVELOPING:
				return new EnvelopingSignatureBuilder(params, document, certificateVerifier);
			case DETACHED:
				return new DetachedSignatureBuilder(params, document, certificateVerifier);
			default:
				throw new DSSException("Unsupported packaging " + params.getSignaturePackaging());
		}
	}

	static void createTransform(final Document document, final DSSTransform dssTransform, final Element transformDom) {

		transformDom.setAttribute(ALGORITHM, dssTransform.getAlgorithm());

		final String elementName = dssTransform.getElementName();
		final String textContent = dssTransform.getTextContent();
		if (DSSUtils.isNotBlank(elementName)) {

			final String namespace = dssTransform.getNamespace();
			DSSXMLUtils.addTextElement(document, transformDom, namespace, elementName, textContent);
		} else if (DSSUtils.isNotBlank(textContent)) {

			final Document transformContentDoc = DSSXMLUtils.buildDOM(textContent);
			final Element contextDocumentElement = transformContentDoc.getDocumentElement();
			document.adoptNode(contextDocumentElement);
			transformDom.appendChild(contextDocumentElement);
		}
	}

	protected static boolean isXPointer(final String uri) {

		final boolean xPointer = uri.startsWith("#xpointer(") || uri.startsWith("#xmlns(");
		return xPointer;
	}

	protected void setCanonicalizationMethods(final SignatureParameters params, final String canonicalizationMethod) {

		final String signedInfoCanonicalizationMethod_ = params.getSignedInfoCanonicalizationMethod();
		if (DSSUtils.isNotBlank(signedInfoCanonicalizationMethod_)) {
			signedInfoCanonicalizationMethod = signedInfoCanonicalizationMethod_;
		} else {
			signedInfoCanonicalizationMethod = canonicalizationMethod;
		}
		final String signedPropertiesCanonicalizationMethod_ = params.getSignedPropertiesCanonicalizationMethod();
		if (DSSUtils.isNotBlank(signedPropertiesCanonicalizationMethod_)) {
			signedPropertiesCanonicalizationMethod = signedPropertiesCanonicalizationMethod_;
		} else {
			signedPropertiesCanonicalizationMethod = canonicalizationMethod;
		}
	}

	/**
	 * This is the main method which is called to build the XML signature
	 *
	 * @return A byte array is returned with XML that represents the canonicalized <ds:SignedInfo> segment of signature. This data are used to define the <ds:SignatureValue>
	 * element.
	 * @throws DSSException in the case of any Exception
	 */
	public byte[] build() throws DSSException {

		documentDom = getDomDocumentForSignature();

		deterministicId = params.getDeterministicId();

		prepareReferences();

		createSignatureDom();

		final byte[] canonicalizedSignedInfo = canonicalizeSignedInfo();
		built = true;
		return canonicalizedSignedInfo;
	}

	/**
	 * @return the {@code Document} where the signature should be incorporated
	 */
	protected Document getDomDocumentForSignature() {

		return DSSXMLUtils.buildDOM();
	}

	private byte[] canonicalizeSignedInfo() {

		final byte[] canonicalizedSignedInfo = DSSXMLUtils.canonicalizeSubtree(signedInfoCanonicalizationMethod, signedInfoDom);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalized SignedInfo         --> {}", new String(canonicalizedSignedInfo));
			final byte[] digest = DSSUtils.digest(DigestAlgorithm.SHA256, canonicalizedSignedInfo);
			LOG.trace("Canonicalized SignedInfo SHA256  --> {}", DSSUtils.base64Encode(digest));
		}
		return canonicalizedSignedInfo;
	}

	private void createSignatureDom() {

		incorporateSignatureDom();
		incorporateSignedInfo();
		incorporateSignatureValue();
		incorporateKeyInfo();
		incorporateObject();
		incorporateSpecificObjects();

		/**
		 * We create <ds:Reference> segment only now, because we need first to define the SignedProperties segment to
		 * calculate the digest of references.
		 */
		incorporateReferences();
		incorporateReferenceSignedProperties();
	}

	private void prepareReferences() {

		final List<DSSReference> references = params.getReferences();
		if (DSSUtils.isEmpty(references)) {

			final List<DSSReference> defaultReferences = createDefaultReferences();
			// The SignatureParameters object is updated with the default references.
			params.setReferences(defaultReferences);
		}
	}

	/**
	 * This method creates a new instance of Signature element.
	 */
	public void incorporateSignatureDom() {

		signatureDom = documentDom.createElementNS(XMLNS, DS_SIGNATURE);
		signatureDom.setAttribute(XMLNS_DS, XMLNS);
		signatureDom.setAttribute(ID, deterministicId);
		final Node nodeToIncludeSignature = getNodeToIncludeSignature();
		nodeToIncludeSignature.appendChild(signatureDom);
	}

	/**
	 * @return the {@code Element} that will contain the signature
	 */
	protected Node getNodeToIncludeSignature() {

		return documentDom;
	}

	public void incorporateSignedInfo() {

		// <ds:SignedInfo>
		signedInfoDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLNS, DS_SIGNED_INFO);
		incorporateCanonicalizationMethod(signedInfoDom, signedInfoCanonicalizationMethod);

		//<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
		final Element signatureMethod = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLNS, DS_SIGNATURE_METHOD);
		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final DigestAlgorithm digestAlgorithm = params.getDigestAlgorithm();
		final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.getAlgorithm(encryptionAlgorithm, digestAlgorithm);
		final String signatureAlgorithmXMLId = signatureAlgorithm.getXMLId();
		signatureMethod.setAttribute(ALGORITHM, signatureAlgorithmXMLId);
	}

	private void incorporateCanonicalizationMethod(final Element parentDom, final String signedInfoCanonicalizationMethod) {

		//<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element canonicalizationMethodDom = DSSXMLUtils.addElement(documentDom, parentDom, XMLNS, DS_CANONICALIZATION_METHOD);
		canonicalizationMethodDom.setAttribute(ALGORITHM, signedInfoCanonicalizationMethod);
	}

	/**
	 * This method incorporates the references other than the one concerning "http://uri.etsi.org/01903#SignedProperties".
	 *
	 * @throws DSSException
	 */
	protected void incorporateReferences() throws DSSException {

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			incorporateReference(reference);
		}
	}

	/**
	 * Creates KeyInfoType JAXB object.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are included.
	 *
	 * @throws DSSException
	 */
	protected void incorporateKeyInfo() throws DSSException {

		// <ds:KeyInfo>
		final Element keyInfoDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLNS, DS_KEY_INFO);
		// <ds:X509Data>
		final Element x509DataDom = DSSXMLUtils.addElement(documentDom, keyInfoDom, XMLNS, DS_X509_DATA);
		final boolean trustAnchorBPPolicy = params.bLevel().isTrustAnchorBPPolicy();
		final CertificatePool certificatePool = getCertificatePool();
		boolean firstCertificate = true; // The signing certificate can be directly in the TSL
		for (final ChainCertificate chainCertificate : params.getCertificateChain()) {

			final X509Certificate x509Certificate = chainCertificate.getX509Certificate();
			if (trustAnchorBPPolicy && certificatePool != null) {

				if (!certificatePool.get(x509Certificate.getSubjectX500Principal()).isEmpty()) {
					if (firstCertificate) {
						addCertificate(x509DataDom, x509Certificate);
					}
					break;
				}
				firstCertificate = false;
			}
			addCertificate(x509DataDom, x509Certificate);
		}
	}

	private void addCertificate(final Element x509DataDom, final X509Certificate x509Certificate) {

		final byte[] encoded = DSSUtils.getEncoded(x509Certificate);
		final String base64Encoded = DSSUtils.base64Encode(encoded);
		// <ds:X509Certificate>...</ds:X509Certificate>
		DSSXMLUtils.addTextElement(documentDom, x509DataDom, XMLNS, DS_X509_CERTIFICATE, base64Encoded);
	}

	/**
	 * @throws DSSException
	 */
	protected void incorporateObject() throws DSSException {

		// <ds:Object>
		final Element objectDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLNS, DS_OBJECT);

		// <QualifyingProperties xmlns="http://uri.etsi.org/01903/v1.3.2#" Target="#sigId-ide5c549340079fe19f3f90f03354a5965">
		qualifyingPropertiesDom = DSSXMLUtils.addElement(documentDom, objectDom, XAdES, XADES_QUALIFYING_PROPERTIES);
		qualifyingPropertiesDom.setAttribute(XMLNS_XADES, XAdES);
		qualifyingPropertiesDom.setAttribute(TARGET, "#" + deterministicId);

		incorporateSignedProperties();
	}

	/**
	 * To be used in the case of an ENVELOPING signature
	 *
	 * @throws DSSException
	 */
	protected void incorporateSpecificObjects() throws DSSException {

	}

	/**
	 * @throws DSSException
	 */
	protected void incorporateReferenceSignedProperties() throws DSSException {

		// <ds:Reference Type="http://uri.etsi.org/01903#SignedProperties" URI="#xades-ide5c549340079fe19f3f90f03354a5965">
		final Element reference = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLNS, DS_REFERENCE);
		reference.setAttribute(TYPE, xPathQueryHolder.XADES_SIGNED_PROPERTIES);
		reference.setAttribute(URI, "#xades-" + deterministicId);
		// <ds:Transforms>
		final Element transforms = DSSXMLUtils.addElement(documentDom, reference, XMLNS, DS_TRANSFORMS);
		// <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
		final Element transform = DSSXMLUtils.addElement(documentDom, transforms, XMLNS, DS_TRANSFORM);
		transform.setAttribute(ALGORITHM, signedPropertiesCanonicalizationMethod);
		// </ds:Transforms>

		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final DigestAlgorithm digestAlgorithm = params.getSignedPropertiesDigestAlgorithm();
		incorporateDigestMethod(reference, digestAlgorithm);

		// <ds:DigestValue>b/JEDQH2S1Nfe4Z3GSVtObN34aVB1kMrEbVQZswThfQ=</ds:DigestValue>
		final byte[] canonicalizedBytes = DSSXMLUtils.canonicalizeSubtree(signedPropertiesCanonicalizationMethod, signedPropertiesDom);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method  --> {}", signedPropertiesCanonicalizationMethod);
			LOG.trace("Canonicalised REF_2      --> {}", new String(canonicalizedBytes));
		}
		incorporateDigestValue(reference, digestAlgorithm, new InMemoryDocument(canonicalizedBytes));
	}

	/**
	 * This method incorporates a reference within the signedInfoDom
	 *
	 * @param dssReference {@code DSSReference}
	 * @throws DSSException
	 */
	protected void incorporateReference(final DSSReference dssReference) throws DSSException {

		final Element referenceDom = DSSXMLUtils.addElement(documentDom, signedInfoDom, XMLNS, DS_REFERENCE);
		referenceDom.setAttribute(ID, dssReference.getId());
		final String uri = dssReference.getUri();
		referenceDom.setAttribute(URI, uri);
		final String dssReferenceType = dssReference.getType();
		if (DSSUtils.isNotEmpty(dssReferenceType)) {
			referenceDom.setAttribute(TYPE, dssReferenceType);
		}

		final List<DSSTransform> dssTransforms = dssReference.getTransforms();
		if (dssTransforms != null) { // Detached signature may not have transformations

			final Element transformsDom = DSSXMLUtils.addElement(documentDom, referenceDom, XMLNS, DS_TRANSFORMS);
			for (final DSSTransform dssTransform : dssTransforms) {

				final Element transformDom = DSSXMLUtils.addElement(documentDom, transformsDom, XMLNS, DS_TRANSFORM);
				createTransform(documentDom, dssTransform, transformDom);
			}
		}
		// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
		final DigestAlgorithm digestAlgorithm = dssReference.getDigestMethodAlgorithm();
		incorporateDigestMethod(referenceDom, digestAlgorithm);

		final DSSDocument canonicalizedDocument = transformReference(dssReference);
		if (LOG.isTraceEnabled()) {
			LOG.trace("Canonicalization method  -->" + signedInfoCanonicalizationMethod);
			LOG.trace("Canonicalized REF_1      --> " + new String(canonicalizedDocument.getBytes()));
		}
		incorporateDigestValue(referenceDom, digestAlgorithm, canonicalizedDocument);
	}

	/**
	 * This method creates the default references in the case they are not set as a parameter.
	 *
	 * @return {@code List} of {@code DSSReference}s with default values
	 */
	protected abstract List<DSSReference> createDefaultReferences();

	/**
	 * This method performs the reference transformation. Note that for the time being (4.3.0-RC) only two types of transformation are implemented: canonicalization & {@code
	 * Transforms.TRANSFORM_XPATH} and can be applied only for {@code SignaturePackaging.ENVELOPED}.
	 *
	 * @param reference {@code DSSReference} to be transformed
	 * @return {@code DSSDocument} containing transformed reference's data
	 */
	protected abstract DSSDocument transformReference(final DSSReference reference);

	/**
	 * This method incorporates the signature value.
	 */
	protected void incorporateSignatureValue() {

		signatureValueDom = DSSXMLUtils.addElement(documentDom, signatureDom, XMLNS, DS_SIGNATURE_VALUE);
		signatureValueDom.setAttribute(ID, "value-" + deterministicId);
	}

	/**
	 * Creates the SignedProperties DOM object element.
	 *
	 * @throws DSSException
	 */
	protected void incorporateSignedProperties() throws DSSException {

		// <SignedProperties Id="xades-ide5c549340079fe19f3f90f03354a5965">
		signedPropertiesDom = DSSXMLUtils.addElement(documentDom, qualifyingPropertiesDom, XAdES, XADES_SIGNED_PROPERTIES);
		signedPropertiesDom.setAttribute(ID, "xades-" + deterministicId);

		incorporateSignedSignatureProperties();
	}

	/**
	 * Creates the SignedSignatureProperties DOM object element.
	 *
	 * @throws DSSException
	 */
	protected void incorporateSignedSignatureProperties() throws DSSException {

		// <SignedSignatureProperties>
		signedSignaturePropertiesDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, XAdES, XADES_SIGNED_SIGNATURE_PROPERTIES);

		incorporateSigningTime();

		incorporateSigningCertificate();

		incorporateSignedDataObjectProperties();

		incorporateSignatureProductionPlace();

		incorporateSignerRole();

		incorporateCommitmentTypeIndications();

		incorporatePolicy();
	}

	private void incorporatePolicy() {

		final BLevelParameters.Policy signaturePolicy = params.bLevel().getSignaturePolicy();
		if (signaturePolicy != null && signaturePolicy.getId() != null) {

			final Element signaturePolicyIdentifierDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, XADES_SIGNATURE_POLICY_IDENTIFIER);
			final Element signaturePolicyIdDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdentifierDom, XAdES, XADES_SIGNATURE_POLICY_ID);
			if ("".equals(signaturePolicy.getId())) { // implicit

				DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, XAdES, XADES_SIGNATURE_POLICY_IMPLIED);
			} else { // explicit

				final Element sigPolicyIdDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, XAdES, XADES_SIG_POLICY_ID);

				final String signaturePolicyId = signaturePolicy.getId();
				DSSXMLUtils.addTextElement(documentDom, sigPolicyIdDom, XAdES, XADES_IDENTIFIER, signaturePolicyId);

				if (signaturePolicy.getDigestAlgorithm() != null && signaturePolicy.getDigestValue() != null) {

					final Element sigPolicyHashDom = DSSXMLUtils.addElement(documentDom, signaturePolicyIdDom, XAdES, XADES_SIG_POLICY_HASH);

					// <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
					final DigestAlgorithm digestAlgorithm = signaturePolicy.getDigestAlgorithm();
					incorporateDigestMethod(sigPolicyHashDom, digestAlgorithm);

					final byte[] hashValue = signaturePolicy.getDigestValue();
					final String bas64EncodedHashValue = DSSUtils.base64Encode(hashValue);
					DSSXMLUtils.addTextElement(documentDom, sigPolicyHashDom, XMLNS, DS_DIGEST_VALUE, bas64EncodedHashValue);
				}
			}
		}
	}

	/**
	 * Creates SigningTime DOM object element.
	 */
	private void incorporateSigningTime() {

		final Date signingDate = params.bLevel().getSigningDate();
		final XMLGregorianCalendar xmlGregorianCalendar = DSSXMLUtils.createXMLGregorianCalendar(signingDate);
		final String xmlSigningTime = xmlGregorianCalendar.toXMLFormat();

		// <SigningTime>2013-11-23T11:22:52Z</SigningTime>
		final Element signingTimeDom = documentDom.createElementNS(XAdES, XADES_SIGNING_TIME);
		signedSignaturePropertiesDom.appendChild(signingTimeDom);
		final Text textNode = documentDom.createTextNode(xmlSigningTime);
		signingTimeDom.appendChild(textNode);
	}

	/**
	 * Creates SigningCertificate building block DOM object:
	 * <p/>
	 * <SigningCertificate> <Cert> <CertDigest> <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/> <ds:DigestValue>fj8SJujSXU4fi342bdtiKVbglA0=</ds:DigestValue>
	 * </CertDigest> <IssuerSerial> <ds:X509IssuerName>CN=ICA A,O=DSS,C=AA</ds:X509IssuerName> <ds:X509SerialNumber>4</ds:X509SerialNumber> </IssuerSerial> </Cert>
	 * </SigningCertificate>
	 */
	private void incorporateSigningCertificate() {

		final Element signingCertificateDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, xPathQueryHolder.XADES_SIGNING_CERTIFICATE);

		final List<X509Certificate> certificates = new ArrayList<X509Certificate>();
		final List<ChainCertificate> certificateChain = params.getCertificateChain();
		for (final ChainCertificate chainCertificate : certificateChain) {
			if (chainCertificate.isSignedAttribute()) {
				certificates.add(chainCertificate.getX509Certificate());
			}
		}
		incorporateCertificateRef(signingCertificateDom, certificates);
	}

	/**
	 * This method incorporates the SignedDataObjectProperties DOM element <SignedDataObjectProperties> ...<DataObjectFormat ObjectReference="#detached-ref-id">
	 * ......<MimeType>text/plain</MimeType> ...</DataObjectFormat> </SignedDataObjectProperties>
	 */
	private void incorporateSignedDataObjectProperties() {

		signedDataObjectPropertiesDom = DSSXMLUtils.addElement(documentDom, signedPropertiesDom, XAdES, XADES_SIGNED_DATA_OBJECT_PROPERTIES);

		final List<DSSReference> references = params.getReferences();
		for (final DSSReference reference : references) {

			final String dataObjectFormatObjectReference = "#" + reference.getId();

			final Element dataObjectFormatDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_DATA_OBJECT_FORMAT);
			dataObjectFormatDom.setAttribute(OBJECT_REFERENCE, dataObjectFormatObjectReference);

			final Element mimeTypeDom = DSSXMLUtils.addElement(documentDom, dataObjectFormatDom, XAdES, XADES_MIME_TYPE);
			MimeType dataObjectFormatMimeType = getReferenceMimeType(reference);
			DSSXMLUtils.setTextNode(documentDom, mimeTypeDom, dataObjectFormatMimeType.getMimeTypeString());

			if (DSSUtils.isNotBlank(reference.getObjectEncoding())) {

				final Element encodingDom = DSSXMLUtils.addElement(documentDom, dataObjectFormatDom, XAdES, XADES_ENCODING);
				DSSXMLUtils.setTextNode(documentDom, encodingDom, reference.getObjectEncoding());
			}
		}

		incorporateContentTimestamps();
	}

	/**
	 * @param reference the reference to compute
	 * @return the {@code MimeType} of the reference or the default value {@code MimeType.BINARY}
	 */
	protected MimeType getReferenceMimeType(final DSSReference reference) {

		MimeType dataObjectFormatMimeType = reference.getContents().getMimeType();
		if (dataObjectFormatMimeType == null) {
			dataObjectFormatMimeType = MimeType.BINARY;
		}
		return dataObjectFormatMimeType;
	}

	/**
	 * This method incorporate the content-timestamps within the signature being created.
	 */
	private void incorporateContentTimestamps() {

		final List<TimestampToken> contentTimestamps = params.getContentTimestamps();
		if (contentTimestamps == null) {
			return;
		}
		Element allDataObjectsTimestampDom = null;
		Element individualDataObjectsTimestampDom = null;
		for (final TimestampToken contentTimestamp : contentTimestamps) {

			final TimestampType timeStampType = contentTimestamp.getTimeStampType();
			if (ALL_DATA_OBJECTS_TIMESTAMP == timeStampType) {

				if (allDataObjectsTimestampDom == null) {
					allDataObjectsTimestampDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_ALL_DATA_OBJECTS_TIME_STAMP);
				}
				addTimestamp(allDataObjectsTimestampDom, contentTimestamp);

			} else if (INDIVIDUAL_DATA_OBJECTS_TIMESTAMP == timeStampType) {

				if (individualDataObjectsTimestampDom == null) {
					individualDataObjectsTimestampDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_INDIVIDUAL_DATA_OBJECTS_TIME_STAMP);
				}
				addTimestamp(individualDataObjectsTimestampDom, contentTimestamp);
			}
		}
	}

	/**
	 * This method incorporates the signer claimed roleType into signed signature properties.
	 */
	private void incorporateSignerRole() {

		final List<String> claimedSignerRoles = params.bLevel().getClaimedSignerRoles();
		final List<BLevelParameters.CertifiedRole> certifiedSignerRoles = params.bLevel().getCertifiedSignerRoles();
		if (claimedSignerRoles != null || certifiedSignerRoles != null) {

			final Element signerRoleDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, xPathQueryHolder.XADES_SIGNER_ROLE);

			if (claimedSignerRoles != null && !claimedSignerRoles.isEmpty()) {

				final Element claimedRolesDom = DSSXMLUtils.addElement(documentDom, signerRoleDom, XAdES, XADES_CLAIMED_ROLES);
				addClaimedRoles(claimedSignerRoles, claimedRolesDom);
			}

			if (certifiedSignerRoles != null && !certifiedSignerRoles.isEmpty()) {

				final Element certifiedRolesDom = DSSXMLUtils.addElement(documentDom, signerRoleDom, XAdES, xPathQueryHolder.XADES_CERTIFIED_ROLES);
				xPathQueryHolder.addCertifiedRoles(documentDom, certifiedSignerRoles, certifiedRolesDom);
			}
		}
	}

	private void addClaimedRoles(final List<String> claimedRoleList, final Element rolesDom) {

		for (final String claimedRole : claimedRoleList) {

			final Element roleDom = DSSXMLUtils.addElement(documentDom, rolesDom, XAdES, XADES_CLAIMED_ROLE);
			DSSXMLUtils.setTextNode(documentDom, roleDom, claimedRole);
		}
	}

	private void incorporateSignatureProductionPlace() {

		final BLevelParameters.SignerLocation signatureProductionPlace = params.bLevel().getSignerLocation();
		if (signatureProductionPlace != null) {

			final Element signatureProductionPlaceDom = DSSXMLUtils.addElement(documentDom, signedSignaturePropertiesDom, XAdES, xPathQueryHolder.XADES_SIGNATURE_PRODUCTION_PLACE);

			final String city = signatureProductionPlace.getCity();
			if (city != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_CITY, city);
			}

			final String streetAddress = signatureProductionPlace.getStreetAddress();
			if (streetAddress != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_STREET_ADDRESS, streetAddress);
			}

			final String stateOrProvince = signatureProductionPlace.getStateOrProvince();
			if (stateOrProvince != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_STATE_OR_PROVINCE, stateOrProvince);
			}

			final String postalCode = signatureProductionPlace.getPostalCode();
			if (postalCode != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_POSTAL_CODE, postalCode);
			}

			final String country = signatureProductionPlace.getCountry();
			if (country != null) {
				DSSXMLUtils.addTextElement(documentDom, signatureProductionPlaceDom, XAdES, XADES_COUNTRY_NAME, country);
			}
		}
	}

	/**
	 * Below follows the schema definition for this element. <xsd:element name="CommitmentTypeIndication" type="CommitmentTypeIndicationType"/>
	 * <p/>
	 * <xsd:complexType name="CommitmentTypeIndicationType"> ...<xsd:sequence> ......<xsd:element name="CommitmentTypeId" type="ObjectIdentifierType"/> ......<xsd:choice>
	 * .........<xsd:element name="ObjectReference" type="xsd:anyURI" maxOccurs="unbounded"/> .........< xsd:element name="AllSignedDataObjects"/> ......</xsd:choice>
	 * ......<xsd:element name="CommitmentTypeQualifiers" type="CommitmentTypeQualifiersListType" minOccurs="0"/> ...</xsd:sequence> </xsd:complexType> <xsd:complexType
	 * name="CommitmentTypeQualifiersListType"> ...<xsd:sequence> ......<xsd:element name="CommitmentTypeQualifier" type="AnyType" minOccurs="0" maxOccurs="unbounded"/>
	 * ...</xsd:sequence> </xsd:complexType>
	 */
	private void incorporateCommitmentTypeIndications() {

		final List<BLevelParameters.CommitmentTypeIndication> commitmentTypeIndicationList = params.bLevel().getCommitmentTypeIndications();
		if (commitmentTypeIndicationList != null) {

			for (final BLevelParameters.CommitmentTypeIndication commitmentTypeIndication : commitmentTypeIndicationList) {

				final Element commitmentTypeIndicationDom = DSSXMLUtils.addElement(documentDom, signedDataObjectPropertiesDom, XAdES, XADES_COMMITMENT_TYPE_INDICATION);
				final Element commitmentTypeIdDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XAdES, XADES_COMMITMENT_TYPE_ID);
				DSSXMLUtils.addTextElement(documentDom, commitmentTypeIdDom, XAdES, XADES_IDENTIFIER, commitmentTypeIndication.getIdentifier());
				final String description = commitmentTypeIndication.getDescription();
				if (DSSUtils.isNotBlank(description)) {
					DSSXMLUtils.addTextElement(documentDom, commitmentTypeIdDom, XAdES, XADES_DESCRIPTION, description);
				}
				final List<String> documentationReferences = commitmentTypeIndication.getDocumentationReferences();
				if (documentationReferences.size() > 0) {

					final Element documentationReferencesDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIdDom, XAdES, XADES_DOCUMENTATION_REFERENCES);
					for (final String documentationReference : documentationReferences) {
						DSSXMLUtils.addTextElement(documentDom, documentationReferencesDom, XAdES, XADES_DOCUMENTATION_REFERENCE, documentationReference);
					}
				}
				final List<String> objectReferences = commitmentTypeIndication.getObjectReferences();
				if (objectReferences.size() > 0) {

					final List<DSSReference> references = params.getReferences();
					for (final String objectReference : objectReferences) {
						for (final DSSReference reference : references) {
							if (objectReference.equals(reference.getUri())) {
								DSSXMLUtils.addTextElement(documentDom, commitmentTypeIndicationDom, XAdES, XADES_OBJECT_REFERENCE, "#" + reference.getId());
							}
						}
					}
				} else {
					DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XAdES, XADES_ALL_SIGNED_DATA_OBJECTS);
				}
				//final Element commitmentTypeQualifiersDom = DSSXMLUtils.addElement(documentDom, commitmentTypeIndicationDom, XADES, "CommitmentTypeQualifiers");
			}
		}
	}

	/**
	 * Adds signature value to the signature and returns XML signature {@code DSSDocument} (InMemoryDocument)
	 *
	 * @param signatureValue - Encoded value of the signature
	 * @return {@code DSSDocument}
	 * @throws DSSException
	 */
	public DSSDocument signDocument(final byte[] signatureValue) throws DSSException {

		if (!built) {
			build();
		}
		final EncryptionAlgorithm encryptionAlgorithm = params.getEncryptionAlgorithm();
		final byte[] signatureValueBytes = DSSSignatureUtils.convertToXmlDSig(encryptionAlgorithm, signatureValue);
		final String signatureValueBase64Encoded = DSSUtils.base64Encode(signatureValueBytes);

		final Text signatureValueNode = documentDom.createTextNode(signatureValueBase64Encoded);
		signatureValueDom.appendChild(signatureValueNode);

		byte[] documentBytes = DSSXMLUtils.transformToByteArray(documentDom);
		final InMemoryDocument inMemoryDocument = new InMemoryDocument(documentBytes);
		inMemoryDocument.setMimeType(MimeType.XML);
		return inMemoryDocument;
	}

	/**
	 * Adds the content of a timestamp into the given timestamp element
	 *
	 * @param timestampElement {@code Element} where the timestamp should be incorporated
	 * @param timestampToken   {@code TimestampToken} to be incorporated
	 */
	protected void addTimestamp(final Element timestampElement, final TimestampToken timestampToken) {

		//List<TimestampInclude> includes, String canonicalizationMethod, TimestampToken encapsulatedTimestamp) {
		//add includes: URI + referencedData = "true"
		//add canonicalizationMethod: Algorithm
		//add encapsulatedTimestamp: Encoding, Id, while its textContent is the base64 encoding of the data to digest
		final List<TimestampInclude> includes = timestampToken.getTimestampIncludes();
		if (includes != null) {

			for (final TimestampInclude include : includes) {

				final Element timestampIncludeElement = documentDom.createElementNS(XAdES, XADES_INCLUDE);
				timestampIncludeElement.setAttribute(URI, "#" + include.getURI());
				timestampIncludeElement.setAttribute(REFERENCED_DATA, "true");
				timestampElement.appendChild(timestampIncludeElement);
			}
		}
		final Element canonicalizationMethodElement = documentDom.createElementNS(XMLNS, DS_CANONICALIZATION_METHOD);
		canonicalizationMethodElement.setAttribute(ALGORITHM, timestampToken.getCanonicalizationMethod());

		timestampElement.appendChild(canonicalizationMethodElement);

		Element encapsulatedTimestampElement = documentDom.createElementNS(XAdES, XADES_ENCAPSULATED_TIME_STAMP);
		encapsulatedTimestampElement.setTextContent(DSSUtils.base64Encode(timestampToken.getEncoded()));

		timestampElement.appendChild(encapsulatedTimestampElement);
	}
}