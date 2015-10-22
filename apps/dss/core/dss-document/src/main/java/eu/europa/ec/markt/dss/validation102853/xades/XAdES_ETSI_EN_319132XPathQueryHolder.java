package eu.europa.ec.markt.dss.validation102853.xades;

import java.security.cert.X509Certificate;
import java.util.List;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.signature.BLevelParameters;

import static eu.europa.ec.markt.dss.XAdESNamespaces.XAdES;

/**
 * Encapsulates specific tag names related to Draft ETSI EN 319 132-1 V1.0.0 (2015-06).
 *
 * @author Robert Bielecki
 */
public class XAdES_ETSI_EN_319132XPathQueryHolder extends XPathQueryHolder {

	public static final String XADES_X509_ATTRIBUTE_CERTIFICATE = "xades:X509AttributeCertificate";

	public XAdES_ETSI_EN_319132XPathQueryHolder() {

		XADES_SIGNING_CERTIFICATE = "xades:SigningCertificateV2";
		XADES_ISSUER_SERIAL = "xades:IssuerSerialV2";
		XADES_SIGNATURE_PRODUCTION_PLACE = "xades:SignatureProductionPlaceV2";
		XADES_SIGNER_ROLE = "xades:SignerRoleV2";
		XADES_CERTIFIED_ROLES = "xades:CertifiedRolesV2";

		// TODO-Bob (21/10/2015): xades141:CompleteCertificateRefsV2
	}

	@Override
	public void incorporateIssuerSerial(final Document documentDom, final X509Certificate certificate, final Element certDom) {

	}

	@Override
	public void addCertifiedRoles(final Document documentDom, final List<BLevelParameters.CertifiedRole> certifiedRoleList, final Element rolesDom) {

		for (final BLevelParameters.CertifiedRole certifiedRole : certifiedRoleList) {

			final Element roleDom = DSSXMLUtils.addElement(documentDom, rolesDom, XAdES, XADES_CERTIFIED_ROLE);
			final Element x509AttributeCertificateDom = DSSXMLUtils.addElement(documentDom, roleDom, XAdES, XADES_X509_ATTRIBUTE_CERTIFICATE);
			DSSXMLUtils.setTextNode(documentDom, x509AttributeCertificateDom, certifiedRole.getAttributeCertificateBase64Encoded());
			x509AttributeCertificateDom.setAttribute(ENCODING, certifiedRole.getEncoding());

		}
	}
}
