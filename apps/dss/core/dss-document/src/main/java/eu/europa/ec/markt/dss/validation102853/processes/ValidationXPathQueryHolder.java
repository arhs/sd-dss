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

	String XP_MANIFEST_ROOT = "./dss:BasicSignature/dss:References/dss:Reference[@Type='http://www.w3.org/2000/09/xmldsig#Manifest']";
	String XP_MANIFEST_REFERENCE_FOUND = "boolean(" + XP_MANIFEST_ROOT + ")";
	String XP_MANIFEST_REFERENCE = "/dss:ManifestReferences/dss:Reference";
	String XP_MANIFEST_REFERENCE_INTACT = XP_MANIFEST_ROOT + XP_MANIFEST_REFERENCE + "/dss:ReferenceDataIntact/text()";
	String XP_MANIFEST_REFERENCE_DATA_FOUND = XP_MANIFEST_ROOT + XP_MANIFEST_REFERENCE + "/dss:ReferenceDataFound/text()";
	String XP_MANIFEST_REFERENCE_URI = XP_MANIFEST_ROOT + XP_MANIFEST_REFERENCE + "/dss:Uri/text()";
	String XP_MANIFEST_REFERENCE_REAL_URI = XP_MANIFEST_ROOT + XP_MANIFEST_REFERENCE + "/dss:RealUri/text()";
	String XP_MANIFEST_DIGEST_ALGORITHM = XP_MANIFEST_ROOT + XP_MANIFEST_REFERENCE + "/dss:DigestMethod/text()";

	String XP_MANIFEST_REFERENCE_COUNT = "count(" + XP_MANIFEST_ROOT + ")";

	String XP_MANIFEST_CONSTRAINT = "boolean(/ConstraintsParameters/MainSignature/Manifest)";
}
