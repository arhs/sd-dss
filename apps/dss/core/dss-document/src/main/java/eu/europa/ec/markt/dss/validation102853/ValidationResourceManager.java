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
package eu.europa.ec.markt.dss.validation102853;

import java.io.InputStream;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Marshaller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

import eu.europa.ec.markt.dss.DSSXMLUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.DiagnosticData;
import eu.europa.ec.markt.dss.validation102853.data.diagnostic.ObjectFactory;

public class ValidationResourceManager {

	private static final Logger LOG = LoggerFactory.getLogger(ValidationResourceManager.class);

	public static String defaultPolicyConstraintsLocation = "/102853/policy/constraint.xml";
	public static String defaultCountersignaturePolicyConstraintsLocation = "/102853/policy/countersignature-constraint.xml";
	public static String defaultTslPolicyConstraintsLocation = "/102853/policy/tsl-constraint.xml";

	private static JAXBContext jaxbContext;

	static {

		try {
			jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
		} catch (JAXBException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This method loads the policy constraint file. If the validationPolicy is not specified then the default policy file is
	 * loaded.
	 *
	 * @param policyDataStream
	 * @return
	 */
	public static Document loadPolicyData(InputStream policyDataStream) {

		if (policyDataStream != null) {

			return load(policyDataStream);
		}
		if (defaultPolicyConstraintsLocation != null && !defaultPolicyConstraintsLocation.isEmpty()) {

			return load(defaultPolicyConstraintsLocation);
		}
		return null;
	}

	/**
	 * This method loads the countersignature policy constraint file. If the validationPolicy is not specified then the default policy file is
	 * loaded.
	 *
	 * @param policyDataStream
	 * @return
	 */
	public static Document loadCountersignaturePolicyData(final InputStream policyDataStream) {

		if (policyDataStream != null) {

			return load(policyDataStream);
		}
		if (defaultCountersignaturePolicyConstraintsLocation != null && !defaultCountersignaturePolicyConstraintsLocation.isEmpty()) {

			return load(defaultCountersignaturePolicyConstraintsLocation);
		}
		return null;
	}

	/**
	 * This method loads the TSL policy constraint file. If the validationPolicy is not specified then the default policy file is
	 * loaded.
	 *
	 * @param policyDataStream
	 * @return
	 */
	public static Document loadTslPolicyData(final InputStream policyDataStream) {

		if (policyDataStream != null) {

			return load(policyDataStream);
		}
		if (defaultTslPolicyConstraintsLocation != null && !defaultTslPolicyConstraintsLocation.isEmpty()) {

			return load(defaultTslPolicyConstraintsLocation);
		}
		return null;
	}

	/**
	 * This method loads the data from the resource file into an {@link java.io.InputStream}.
	 *
	 * @param dataFileName
	 * @return
	 */
	public static InputStream getResourceInputStream(final String dataFileName) {

		try {
			// final URL resource = ValidationResourceManager.class.getResource("/");
			// System.out.println(resource.getPath());
			InputStream inputStream = ValidationResourceManager.class.getResourceAsStream(dataFileName);
			// DSSUtils.copy(inputStream, System.out);
			return inputStream;
		} catch (Exception e) {
			throw new DSSException(e);
		}
	}

	/**
	 * This is the utility method that loads the data from the file determined by the path parameter into a
	 * {@link org.w3c.dom.Document}.
	 *
	 * @param path
	 * @return
	 */
	public static Document load(final String path) {

		if (path == null || path.isEmpty()) {

			return null;
		}
		final InputStream fileInputStream = getResourceInputStream(path);
		if (fileInputStream == null) {
			LOG.warn("path: '{}'", path);
		}
		final Document document = load(fileInputStream);
		// DSSXMLUtils.printDocument(document, System.out);
		return document;
	}

	/**
	 * This is the utility method that loads the data from the inputstream determined by the inputstream parameter into a
	 * {@link org.w3c.dom.Document}.
	 *
	 * @param inputStream
	 * @return
	 */
	public static Document load(final InputStream inputStream) throws DSSException {

		final Document document = DSSXMLUtils.buildDOM(inputStream);
		return document;
	}

	/**
	 * This is the utility method that marshals the JAXB object into a {@link org.w3c.dom.Document}.
	 *
	 * @param diagnosticDataJB The JAXB object representing the diagnostic data.
	 * @return
	 */
	public static Document convert(final DiagnosticData diagnosticDataJB) {

		try {

			final Document diagnosticData = DSSXMLUtils.buildDOM();
			Marshaller marshaller = jaxbContext.createMarshaller();
			marshaller.setProperty(Marshaller.JAXB_FORMATTED_OUTPUT, Boolean.TRUE);
			marshaller.marshal(diagnosticDataJB, diagnosticData);
			return diagnosticData;
		} catch (JAXBException e) {
			throw new DSSException(e);
		}
	}
}
