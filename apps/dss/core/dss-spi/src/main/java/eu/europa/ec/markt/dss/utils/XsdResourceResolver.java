package eu.europa.ec.markt.dss.utils;

import java.io.InputStream;

import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.ResourceLoader;

/**
 * TODO
 *
 * @author Robert Bielecki
 */
public class XsdResourceResolver implements LSResourceResolver {

	public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {

		// note: in this sample, the XSD's are expected to be in the root of the classpath

		// http://uri.etsi.org/01903/v1.3.2/XAdES.xsd
		// http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd
		// http://www.w3.org/2001/XMLSchema.dtd
		// datatypes.dtd
		final ResourceLoader resourceLoader = new ResourceLoader();
		InputStream resourceAsStream = null;
		if ("http://uri.etsi.org/01903/v1.3.2/XAdES.xsd".equals(systemId)) {
			resourceAsStream = resourceLoader.getResource(DSSXMLUtils.XAD_ESV132_XSD);
		} else if ("http://uri.etsi.org/01903/v1.3.2/XAdES01903v132-201506.xsd".equals(systemId)) {
			resourceAsStream = resourceLoader.getResource(DSSXMLUtils.XAD_ESV132_201506_XSD);
		} else if("http://www.w3.org/TR/2008/REC-xmldsig-core-20080610/xmldsig-core-schema.xsd".equals(systemId)) {
			resourceAsStream = resourceLoader.getResource(DSSXMLUtils.XMLDSIG_CORE_SCHEMA_20080610_XSD);
		} else if ("http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/xmldsig-core-schema.xsd".equals(systemId)) {
			resourceAsStream = resourceLoader.getResource(DSSXMLUtils.XMLDSIG_CORE_SCHEMA_XSD);
		} else if ("http://www.w3.org/2001/XMLSchema.dtd".equals(systemId)) {
			resourceAsStream = resourceLoader.getResource(DSSXMLUtils.XML_SCHEMA_DTD);
		} else if ("datatypes.dtd".equals(systemId)) {
			resourceAsStream = resourceLoader.getResource(DSSXMLUtils.DATA_TYPES_DTD);
		} else {

			System.out.println("!!!!!!!!!! Unknown schema: " + systemId);
		}
		return new XsdInput(publicId, systemId, resourceAsStream);
	}
}
