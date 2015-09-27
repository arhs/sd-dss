package eu.europa.ec.markt.dss.validation102853.processes;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public interface ValidationXPathQueryHolder {

	String XP_REFERENCE_DATA_FOUND = "./BasicSignature/ReferenceDataFound/text()";
	String XP_REFERENCE_DATA_INTACT = "./BasicSignature/ReferenceDataIntact/text()";
	String XP_SIGNATURE_INTACT = "./BasicSignature/SignatureIntact/text()";
	String XP_SIGNATURE_VALID = "./BasicSignature/SignatureValid/text()";

	String XP_MESSAGE_IMPRINT_DATA_FOUND = "./MessageImprintDataFound/text()";
	String XP_MESSAGE_IMPRINT_DATA_INTACT = "./MessageImprintDataIntact/text()";

	String XP_ENCRYPTION_ALGO_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/EncryptionAlgoUsedToSignThisToken/text()";
	String XP_DIGEST_ALGO_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/DigestAlgoUsedToSignThisToken/text()";
	String XP_KEY_LENGTH_USED_TO_SIGN_THIS_TOKEN = "./BasicSignature/KeyLengthUsedToSignThisToken/text()";

	String XP_MANIFEST_REFERENCE_FOUND = "boolean(./dss:BasicSignature/dss:References/dss:Reference[@Type='http://www.w3.org/2000/09/xmldsig#Manifest'])";
	String XP_MANIFEST_REFERENCE_INTACT = "./dss:BasicSignature/dss:References/dss:Reference[@Type='http://www.w3.org/2000/09/xmldsig#Manifest']/dss:ManifestReferences/dss:Reference/dss:ReferenceDataIntact/text()";
	String XP_MANIFEST_REFERENCE_URI = "./dss:BasicSignature/dss:References/dss:Reference[@Type='http://www.w3.org/2000/09/xmldsig#Manifest']/dss:ManifestReferences/dss:Reference/dss:URI/text()";
}
