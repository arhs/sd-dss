package eu.europa.ec.markt.dss.validation102853.xades.xmldsig;
import org.apache.xml.security.algorithms.SignatureAlgorithm;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.MissingResourceFailureException;
import org.apache.xml.security.signature.SignedInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Handles <code>&lt;ds:SignedInfo&gt;</code> elements
 * This <code>SignedInfo<code> element includes the canonicalization algorithm,
 * a signature algorithm, and one or more references.
 *
 * @author Christian Geuer-Pollmann
 */
public class DSSSignedInfo extends SignedInfo {

	public DSSSignedInfo(Document doc, String signatureMethodURI,
			int hMACOutputLength, String canonicalizationMethodURI)
			throws XMLSecurityException {
		super(doc, signatureMethodURI, hMACOutputLength, canonicalizationMethodURI);

	}

	public DSSSignedInfo(Document doc, Element signatureMethodElem,
			Element canonicalizationMethodElem) throws XMLSecurityException {
		super(doc, signatureMethodElem, canonicalizationMethodElem);
	}

	public DSSSignedInfo(Element element, String baseURI,
			boolean secureValidation) throws XMLSecurityException {
		super(element, baseURI, secureValidation);
	}
	
	
	@Override
	protected SignatureAlgorithm getSignatureAlgorithm() {	
		return super.getSignatureAlgorithm();
	}
	
	@Override
	public boolean verifyReferences(boolean followManifests)
			throws MissingResourceFailureException, XMLSecurityException {
		
		//return super.verifyReferences(followManifests);
		return true;
	}

	@Override
	public boolean verify(boolean followManifests)
			throws MissingResourceFailureException, XMLSecurityException {		
		return verifyReferences(followManifests);
	}
	
	
	
    
}
