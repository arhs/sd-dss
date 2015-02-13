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

package eu.europa.ec.markt.dss.validation102853.tsp;

import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampRequestGenerator;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;

/**
 * Class encompassing a RFC 3161 TSA, accessed through HTTP(S) to a given URI
 *
 * @version $Revision$ - $Date$
 */

public class OnlineTSPSource implements TSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(OnlineTSPSource.class);

	public static final String CONTENT_TYPE = "application/timestamp-query";
	public static final String ACCEPT = "application/timestamp-reply";

	/**
	 * A {@code String} representation of a URL of the timestamp server.
	 */
	protected String tspServerUrl;

	/**
	 * The reqPolicy field, if included, indicates the TSA policy under which the TimeStampToken SHOULD be provided.
	 */
	protected ASN1ObjectIdentifier reqPolicyOid;

	/**
	 * If the certReq field is present and set to true, the TSA's public key certificate that is referenced by the ESSCertID identifier inside a
	 * SigningCertificate attribute in the response MUST be provided by the TSA in the certificates field from the SignedData structure in that response.
	 */
	protected boolean certReq = true;

	/**
	 * Replay attack detection: large random number with a high probability that it is generated only once.
	 */
	protected TSPNonceSource tspNonceSource;

	/**
	 * The data loader used to retrieve the timestamp.
	 */
	protected DataLoader dataLoader;

	/**
	 * The default constructor for OnlineTSPSource.
	 */
	public OnlineTSPSource() {
	}

	/**
	 * Build a OnlineTSPSource that will query the specified URL
	 *
	 * @param tspServerUrl
	 */
	public OnlineTSPSource(final String tspServerUrl) {
		this.tspServerUrl = tspServerUrl;
	}

	/**
	 * Set the URL to access the TSA
	 *
	 * @param tspServerUrl
	 */
	public void setTspServerUrl(final String tspServerUrl) {
		this.tspServerUrl = tspServerUrl;
	}

	/**
	 * @return the URL to access the TSA
	 */
	public String getTspServerUrl() {
		return tspServerUrl;
	}

	@Override
	public void setReqPolicyOid(final String reqPolicyOid) {
		this.reqPolicyOid = new ASN1ObjectIdentifier(reqPolicyOid);
	}

	/**
	 * @return the request policy OID
	 */
	public String getReqPolicyOid() {
		return reqPolicyOid.toString();
	}

	@Override
	public String getUniqueId(final byte[] digestValue) {

		final byte[] digest = DSSUtils.digest(DigestAlgorithm.MD5, digestValue, tspNonceSource.getNonce().toByteArray());
		return DSSUtils.encodeHexString(digest);
	}

	public void setTspNonceSource(final TSPNonceSource tspNonceSource) {
		this.tspNonceSource = tspNonceSource;
	}

	public TSPNonceSource getTspNonceSource() {
		return tspNonceSource;
	}

	/**
	 * Allows to indicate if the signing certificate MUST be provided by the TSA in the response.
	 *
	 * @param certReq if true the signing certificate is provided in the response
	 */
	public void setCertReq(boolean certReq) {
		this.certReq = certReq;
	}

	/**
	 * @return indicates if the signing certificate MUST be provided by the TSA in the response
	 */
	public boolean isCertReq() {
		return certReq;
	}

	/**
	 * This method allows to set the {@code DataLoader} to be used to communicate with the TSA.
	 *
	 * @param dataLoader {@code DataLoader}
	 */
	public void setDataLoader(final DataLoader dataLoader) {
		this.dataLoader = dataLoader;
	}

	/**
	 * This method returns the underlying {@code DataLoader}. Note that when the loader is not set an instance of a default loader is created.
	 *
	 * @return {@code DataLoader}
	 */
	public DataLoader getDataLoader() {
		if (dataLoader == null) {
			dataLoader = getDefaultDataLoader();
		}
		return dataLoader;
	}

	/**
	 * This method provides a default {@code DataLoader} to be used when communicating with the timestamp server. This method can be overloaded.
	 *
	 * @return {@code CommonsDataLoader}
	 */
	protected CommonsDataLoader getDefaultDataLoader() {

		final CommonsDataLoader commonsDataLoader = new CommonsDataLoader(CONTENT_TYPE);
		return commonsDataLoader;
	}

	@Override
	public TimeStampToken getTimeStampResponse(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException {

		traceTimestampRequest(digestAlgorithm, digest);
		final byte[] requestBytes = generateTimestampRequest(digestAlgorithm, digest);
		final DataLoader currentDataLoader = getDataLoader();
		final byte[] respBytes = currentDataLoader.post(tspServerUrl, requestBytes);
		final TimeStampResponse timeStampResponse = DSSUtils.newTimeStampResponse(respBytes);
		traceTimestampResponse(timeStampResponse);
		final TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
		return timeStampToken;
	}

	/**
	 * Setup the time stamp request
	 *
	 * @param digestAlgorithm {@code DigestAlgorithm} used to generate the message imprint
	 * @param digest          digest value as byte array
	 * @return array of bytes representing the {@code TimeStampRequest}
	 * @throws DSSException
	 */
	private byte[] generateTimestampRequest(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException {

		final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
		tsqGenerator.setCertReq(certReq);
		if (reqPolicyOid != null) {
			tsqGenerator.setReqPolicy(reqPolicyOid);
		}
		final ASN1ObjectIdentifier asn1ObjectIdentifier = digestAlgorithm.getOid();
		final BigInteger nonce = getNonce();
		final TimeStampRequest request = tsqGenerator.generate(asn1ObjectIdentifier, digest, nonce);
		return DSSUtils.getEncoded(request);
	}

	private static void traceTimestampResponse(final TimeStampResponse timeStampResponse) {

		if (LOG.isTraceEnabled()) {
			final int status = timeStampResponse.getStatus();
			LOG.trace("Status: " + (status == 0 ? "granted (0) --> you got exactly what you asked for." : timeStampResponse.getStatusString()));
		}
	}

	private static void traceTimestampRequest(final DigestAlgorithm digestAlgorithm, final byte[] digest) {

		if (LOG.isTraceEnabled()) {
			LOG.trace("Timestamp digest algorithm: " + digestAlgorithm.getName());
			LOG.trace("Timestamp digest value    : " + DSSUtils.toHex(digest));
		}
	}

	private BigInteger getNonce() {

		if (tspNonceSource == null) {
			tspNonceSource = new TSPNonceSource();
		}
		return tspNonceSource.getNonce();
	}
}
