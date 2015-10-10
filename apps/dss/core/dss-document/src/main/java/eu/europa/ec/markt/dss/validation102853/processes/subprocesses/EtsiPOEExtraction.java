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

package eu.europa.ec.markt.dss.validation102853.processes.subprocesses;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.process.POEExtraction;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;

/**
 * 9.2.3 POE extraction<br>
 * <p/>
 * 9.2.3.1 Description<br>
 * <p/>
 * This building block derives POEs from a given time-stamp. This process assumes the following about the time-stamp:<br>
 * <p/>
 * • The time-stamp has been accepted as VALID.<br>
 * • The cryptographic hash function used in the time-stamp (MessageImprint.hashAlgorithm) is considered reliable at the
 * generation time of the time-stamp.<br>
 * <p/>
 * In the simple case, a time-stamp gives a POE for each data item protected by the time-stamp at the generation
 * date/time of the token. For instance, a time-stamp on the signature value gives a POE of the signature value (the
 * binary data) at the generation date/time of the time-stamp.<br>
 * A time-stamp may also give an indirect POE when it is computed on the hash value of some data instead of the data
 * itself. In this case, we will use the following property (indirect POE):<br>
 * <p/>
 * • If we have a POE for h(d) at a date T1, where h is a cryptographic hash function and d is some data (e.g. a
 * certificate).<br>
 * • And h is asserted in the cryptographic constraints to be trusted until at least a date T after T1.<br>
 * • And we have a POE for d at a date T after T1.<br>
 * <p/>
 * Then, we can derive from the time-stamp a POE for d at T1.
 * <p/>
 * 9.2.3.2 Input<br>
 * - Signature ............................ Mandatory<br>
 * - An attribute with a time-stamp token . Mandatory<br>
 * - A set of POEs ........................ Mandatory (but may be empty)<br>
 * - Cryptographic constraints ............ Optional<br>
 * <p/>
 * 9.2.3.3 Output<br>
 * - A set of POEs.<br>
 * <p/>
 * 9.2.3.4 Processing<br>
 * <p/>
 * The following steps shall be performed, depending on the type of the AdES time-stamp:<br>
 * <p/>
 * 9.2.3.4.1 Extraction from a time-stamp on the signature<br>
 * <p/>
 * Return the set of POEs resulting from the following: add a POE for the signature value at the generation time of the
 * time-stamp.<br>
 * <p/>
 * NOTE: It is possible to infer an indirect POE for the signed data objects (including the signed attributes). However,
 * this is true for some signature algorithms but not all of them (in particular this require that the signature
 * algorithm has the message recovery property and that we have a proof of existence of the public key at the generation
 * time of the time-stamp).<br>
 * <p/>
 * 9.2.3.4.2 Extraction from a time-stamp on certificates and revocation references<br>
 * <p/>
 * Return the set of POEs resulting from the following. All the POEs are added with the generation time of the
 * time-stamp on certificates and revocation references.<br>
 * <p/>
 * For each reference in the attribute complete-certificate-references and complete-revocation-reference:<br>
 * <p/>
 * 1) Add a POE for the hash value h(C) of the certificate C (respectively h(R) of the revocation status information R).<br>
 * <p/>
 * 2) If the set of POEs includes a POE for a certificate C (respectively a revocation status information R) at a
 * date/time T after the generation date/time of the time-stamp, add a POE for C (respectively R).<br>
 * <p/>
 * 9.2.3.4.3 Extraction from a time-stamp on the signature and certificates and revocation references<br>
 * <p/>
 * Return the set of POEs resulting from the following. All the POEs are added with the generation time of the
 * time-stamp on the signature and certificates and revocation references:<br>
 * <p/>
 * 1) Do the extraction process from a time-stamp on the signature (see clause 9.2.3.4.1).<br>
 * 2) Do the extraction process from a time-stamp on certificates and revocation references (see clause 9.2.3.4.2).<br>
 * <p/>
 * 9.2.3.4.4 Extraction from an archive-time-stamp<br>
 * <p/>
 * Return the set of POEs resulting from the following. All the POEs are added with the generation time of the archive
 * time-stamp:<br>
 * <p/>
 * 1) Add a POE for each signed object.<br>
 * 2) Add a POE for the signature value.<br>
 * 3) Add a POE for each certificate and revocation status information present in the signature.<br>
 * 4) Add a POE for each signed and unsigned attribute (except the attribute containing this archive time-stamp and any
 * archive-time-stamp attribute added after this attribute) present in the signature. This implicitly includes the
 * addition of a POE (direct or indirect POE) for any time-stamp, certificate or revocation information status
 * encapsulated in these attributes.<br>
 * <p/>
 * 9.2.3.4.5 Extraction from a long-term-validation attribute<br>
 * <p/>
 * This process applies only to CAdES [1]. If the long-term-validation attribute does not include the poeValue field, no
 * POEs are extracted. If the poeValue field is present with a time-stamp, perform the process below. Processing
 * poeValue field when an ERS [17] is present is out of the scope of the present document.
 * <p/>
 * Return the set of POEs resulting from the following. All the POEs are added with the generation time of the
 * time-stamp present in the poeValue:<br>
 * <p/>
 * 1) Add a POE for the signed object if available in the SignedData.<br>
 * 2) Add a POE for the signature value.<br>
 * 3) Add a POE for each certificate (respectively revocation information status) in SignedData.certificates
 * (respectively in SignedData.crls) or in long-term-validation.extraCertificates (respectively in long-term-validation.
 * extraRevocation).<br>
 * 4) Add a POE for each signed and unsigned attribute (except the attribute containing this poeValue and the
 * long-term-validation attributes added after it). This implicitly includes the addition of a POE (direct or indirect
 * POE) for any time-stamp, certificate or revocation information status encapsulated in these attributes.<br>
 * <p/>
 * // This is the part of the new CAdES specification:<br>
 * // http://www.etsi.org/deliver/etsi_ts/101700_101799/101733/02.01.01_60/ts_101733v020101p.pdf<br>
 * <p/>
 * 9.2.3.4.6 Extraction from a PDF document time-stamp<br>
 * <p/>
 * This process applies only to PAdES [14]. Return the set of POEs resulting from the following. All the POEs are added
 * with the generation time of the document time-stamp:<br>
 * <p/>
 * 1) Add a POE for any SignedData included in the ByteRange protected by the document time-stamp. This implicitly
 * includes the addition of a POE (direct or indirect POE) for any time-stamp token, certificate or revocation
 * information status encapsulated in these SignedData.<br>
 * 2) Add a POE for each certificate or revocation information status in a Document Security Store included in the
 * ByteRange protected by the document time-stamp.<br>
 * 3) Add a POE for each document time-stamp included in the ByteRange protected by the document time-stamp. This
 * implicitly includes the addition of a POE (direct or indirect POE) for any certificate or revocation information
 * status encapsulated in these time-stamps.<br>
 *
 * @author bielecro
 */
public class EtsiPOEExtraction extends POEExtraction {

	private static final Logger LOG = LoggerFactory.getLogger(EtsiPOEExtraction.class);

	private Map<String, List<Date>> signaturePOEList = new HashMap<String, List<Date>>();
	private Map<Integer, List<Date>> certificatePOEList = new HashMap<Integer, List<Date>>();

	/**
	 * Extraction and addition of POE from the given timestamp
	 *
	 * @param timestampXmlDom
	 * @param certPool
	 */
	public void addPOE(final XmlDom timestampXmlDom, final XmlDom certPool) {

		final Date date = timestampXmlDom.getTimeValue("./ProductionTime/text()");
		if (date == null) {
			throw new DSSException(EXCEPTION_TPTCBN);
		}
		LOG.debug("Extraction of POE from the timestamp at: " + date);
		final List<XmlDom> signedObjectXmlDomList = timestampXmlDom.getElements("./SignedObjects/*");
		for (final XmlDom signedObjectXmlDom : signedObjectXmlDomList) {

			final String nodeName = signedObjectXmlDom.getName();
			if (SIGNED_SIGNATURE.equals(nodeName)) {

				final String signatureId = signedObjectXmlDom.getAttribute(ID);
				addSignaturePoe(signatureId, date);
				continue;
			}
			final String category = signedObjectXmlDom.getAttribute(CATEGORY);
			final String digestValue = signedObjectXmlDom.getValue("./DigestValue/text()");
			if (CERTIFICATE.toUpperCase().equals(category)) {

				try {

					final Integer certificateId = certPool.getIntValue("./dss:Certificate/dss:DigestAlgAndValue[dss:DigestValue='%s']/../@Id", digestValue);
					addCertificatePoe(certificateId, date);
				} catch (Exception e) {

					LOG.error(String.format("The certificate with digest value:%S is not found.", digestValue));
					// The algorithm continue, this is not blocking issue.
				}
			} else {

				// Revocations
			}
		}
	}

	/**
	 * This method adds the POE for a given signature id and date.
	 *
	 * @param id
	 * @param date
	 */
	private void addSignaturePoe(final String id, final Date date) {

		List<Date> dates = signaturePOEList.get(id);
		if (dates == null) {

			dates = new ArrayList<Date>();
			signaturePOEList.put(id, dates);
		}
		if (!dates.contains(date)) {

			dates.add(date);
		}
	}

	/**
	 * This method adds the POE for a given certificate id and date.
	 *
	 * @param id
	 * @param date
	 */
	private void addCertificatePoe(final Integer id, final Date date) {

		List<Date> dates = certificatePOEList.get(Integer.toString(id));
		if (dates == null) {

			dates = new ArrayList<Date>();
			certificatePOEList.put(id, dates);
		}
		if (!dates.contains(date)) {

			dates.add(date);
		}
	}

	/**
	 * Returns true if there is a POE for a given certificate at or before the control time.
	 *
	 * @param certificateId
	 * @param controlTime
	 * @return
	 */
	public boolean getCertificatePOE(final int certificateId, final Date controlTime) {

		List<Date> dates = certificatePOEList.get(certificateId);
		if (dates != null) {
			for (Date date : dates) {
				if (date.compareTo(controlTime) <= 0) {
					return true;
				}
			}
		}
		return false;
	}

	/**
	 * Returns the POE for a given signature at or before the control time.
	 *
	 * @param signatureId
	 * @param controlTime
	 * @return
	 */
	public Date getSignaturePOE(final String signatureId, final Date controlTime) {

		List<Date> dates = signaturePOEList.get(signatureId);
		if (dates != null) {
			for (Date date : dates) {
				if (controlTime.compareTo(date) <= 0) {
					return date;
				}
			}
		}
		return null;
	}

	/**
	 * Returns the lowest POE for a given signature at or before the control time.
	 *
	 * @param signatureId
	 * @param controlTime
	 * @return
	 */
	public Date getLowestSignaturePOE(final String signatureId, final Date controlTime) {

		Date lowestDate = null;
		List<Date> dates = signaturePOEList.get(signatureId);
		if (dates != null) {
			for (Date date : dates) {
				if (date.compareTo(controlTime) <= 0) {
					if (lowestDate == null) {

						lowestDate = date;
					} else if (lowestDate.after(date)) {

						lowestDate = date;
					}
				}
			}
		}
		return lowestDate;
	}

	/**
	 * @return {@code boolean} true if there is at least one POE for certificate or signature
	 */
	public boolean isThereAnyPOE() {
		return (certificatePOEList.size() + signaturePOEList.size()) > 0;
	}
}
