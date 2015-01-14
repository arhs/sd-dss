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

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.tsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.net.URLConnection;

/**
 * Class encompassing a RFC 3161 TSA, accessed through HTTP(S) to a given URI
 *
 * @version $Revision$ - $Date$
 */

public class OnlineTSPSource implements TSPSource, Serializable {

    private static final Logger LOG = LoggerFactory.getLogger(OnlineTSPSource.class);

    private String tspServer;

    private ASN1ObjectIdentifier policyOid;

    private DataLoader dataLoader;
    private String userAgent;

    /**
     * The default constructor for OnlineTSPSource.
     */
    public OnlineTSPSource() {

        this(null);
    }

    /**
     * Build a OnlineTSPSource that will query the specified URL
     *
     * @param tspServer
     */
    public OnlineTSPSource(final String tspServer) {

        this.tspServer = tspServer;
    }

    /**
     * Set the URL of the TSA
     *
     * @param tspServer
     */
    public void setTspServer(final String tspServer) {

        this.tspServer = tspServer;
    }

    /**
     * Set the request policy
     *
     * @param policyOid
     */
    public void setPolicyOid(final String policyOid) {

        this.policyOid = new ASN1ObjectIdentifier(policyOid);

    }

    public DataLoader getDataLoader() {
        return dataLoader;
    }

    public void setDataLoader(final DataLoader dataLoader) {
        this.dataLoader = dataLoader;
    }

    @Override
    public TimeStampToken getTimeStampResponse(final DigestAlgorithm digestAlgorithm, final byte[] digest) throws DSSException {

        try {

			if(LOG.isTraceEnabled()) {

				LOG.trace("Timestamp digest algorithm: " + digestAlgorithm.getName());
				LOG.trace("Timestamp digest value    : " + DSSUtils.toHex(digest));
			}

            // Setup the time stamp request
            final TimeStampRequestGenerator tsqGenerator = new TimeStampRequestGenerator();
            tsqGenerator.setCertReq(true);
            if (policyOid != null) {
                tsqGenerator.setReqPolicy(policyOid);
            }
            final long val = System.currentTimeMillis();
            final BigInteger nonce = BigInteger.valueOf(val);
            final ASN1ObjectIdentifier asn1ObjectIdentifier = digestAlgorithm.getOid();
            final TimeStampRequest request = tsqGenerator.generate(asn1ObjectIdentifier, digest, nonce);
            final byte[] requestBytes = request.getEncoded();

            // Call the communications layer
            byte[] respBytes;
            if (dataLoader != null) {

                respBytes = dataLoader.post(tspServer, requestBytes);
                //if ("base64".equalsIgnoreCase(encoding)) {
                //respBytes = DSSUtils.base64Decode(respBytes);
                //}
            } else {

                respBytes = getTSAResponse(requestBytes);
            }
            // Handle the TSA response
            final TimeStampResponse timeStampResponse = new TimeStampResponse(respBytes);
            LOG.info("Status: " + timeStampResponse.getStatusString());
            final TimeStampToken timeStampToken = timeStampResponse.getTimeStampToken();
            if (timeStampToken != null) {

                LOG.info("SID: " + timeStampToken.getSID());
            }
            return timeStampToken;
        } catch (TSPException e) {
            throw new DSSException("Invalid TSP response", e);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }

    public void setUserAgent (String userAgent) {
        this.userAgent = userAgent;
    }

    /**
     * Get timestamp token - communications layer
     *
     * @return - byte[] - TSA response, raw bytes (RFC 3161 encoded)
     */
    protected byte[] getTSAResponse(final byte[] requestBytes) throws DSSException {

        // Setup the TSA connection
        final URLConnection tsaConnection = DSSUtils.openURLConnection(tspServer);

        tsaConnection.setDoInput(true);
        tsaConnection.setDoOutput(true);
        tsaConnection.setUseCaches(false);
        tsaConnection.setRequestProperty("Content-Type", "application/timestamp-query");
        tsaConnection.setRequestProperty("Content-Transfer-Encoding", "binary");
        if (StringUtils.isNotBlank(userAgent))
          tsaConnection.setRequestProperty("User-Agent", userAgent);

        DSSUtils.writeToURLConnection(tsaConnection, requestBytes);

        // Get TSA response as a byte array
        byte[] respBytes = getReadFromURLConnection(tsaConnection);
        final String encoding = tsaConnection.getContentEncoding();
        if ("base64".equalsIgnoreCase(encoding)) {

            respBytes = DSSUtils.base64Decode(respBytes);
        }
        return respBytes;
    }

    private byte[] getReadFromURLConnection(final URLConnection tsaConnection) throws DSSException {

        try {
            final InputStream inputStream = tsaConnection.getInputStream();
            return DSSUtils.toByteArray(inputStream);
        } catch (IOException e) {
            throw new DSSException(e);
        }
    }
}
