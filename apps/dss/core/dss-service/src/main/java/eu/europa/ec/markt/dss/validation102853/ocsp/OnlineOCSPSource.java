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

package eu.europa.ec.markt.dss.validation102853.ocsp;

import java.io.IOException;
import java.security.Security;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.OCSPException;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPReqBuilder;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.SingleResp;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSRevocationUtils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.CertificatePool;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.OCSPToken;
import eu.europa.ec.markt.dss.validation102853.RevocationToken;
import eu.europa.ec.markt.dss.validation102853.https.OCSPDataLoader;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;

import static org.bouncycastle.asn1.x509.Extension.authorityInfoAccess;
import static org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier;
import static org.bouncycastle.asn1.x509.X509ObjectIdentifiers.ocspAccessMethod;

/**
 * Online OCSP repository. This implementation will contact the OCSP Responder to retrieve the OCSP response.
 *
 * @version $Revision$ - $Date$
 */

public class OnlineOCSPSource implements OCSPSource {

	private static final Logger LOG = LoggerFactory.getLogger(OnlineOCSPSource.class);

	static {

		Security.addProvider(new BouncyCastleProvider());
	}

	/**
	 * In the production environment this variable must be set make more secure the revocation data retrieval. If this variable value is true then the cache system for the OCSP
	 * responses does not work. An identifier of the response without the {@code nonce} extension must be created.
	 */
	public static boolean ADD_NONCE = false;

	/**
	 * The data loader used to retrieve the OCSP response.
	 */
	protected DataLoader dataLoader;

	/**
	 * Create an OCSP source The default constructor for OnlineOCSPSource. The default {@code OCSPDataLoader} is set. It is possible to change it with {@code
	 * #setDataLoader}.
	 */
	public OnlineOCSPSource() {

		dataLoader = new OCSPDataLoader();
	}

	/**
	 * This constructor allows to set a specific {@code DataLoader}.
	 *
	 * @param dataLoader the component that allows to retrieve the data using any protocol: HTTP, HTTPS, FTP, LDAP.
	 * @throws DSSNullException in the case of {@code null} parameter value
	 */
	public OnlineOCSPSource(final DataLoader dataLoader) throws DSSNullException {
		setDataLoader(dataLoader);
	}

	/**
	 * Set the DataLoader to use for querying the OCSP server.
	 *
	 * @param dataLoader the component that allows to retrieve the OCSP response using HTTP.
	 * @throws DSSNullException in the case of {@code null} parameter value
	 */
	public void setDataLoader(final DataLoader dataLoader) throws DSSNullException {

		if (dataLoader == null) {
			throw new DSSNullException(DataLoader.class);
		}
		this.dataLoader = dataLoader;
	}

	@Override
	public OCSPToken getOCSPToken(final CertificateToken certificateToken, final CertificatePool certificatePool) {

		if (certificateToken == null) {
			return null;
		}
		if (certificateToken.getIssuerToken() == null) {
			return null;
		}
		final String ocspAccessLocation = getAccessLocation(certificateToken);
		if (DSSUtils.isEmpty(ocspAccessLocation)) {
			return null;
		}

		final CertificateID certificateId = DSSRevocationUtils.getCertificateID(certificateToken);

		// The nonce extension is used to bind the request to the response, to prevent replay attacks.
		final NonceContainer nonceContainer = getNonceContainer();
		final byte[] ocspRequest = buildOCSPRequest(certificateId, nonceContainer);
		final boolean refresh = shouldCacheBeRefreshed(certificateId);
		final BasicOCSPResp basicOCSPResp = buildBasicOCSPResp(ocspAccessLocation, ocspRequest, refresh);

		checkNonce(certificateToken.getDSSIdAsString(), basicOCSPResp, nonceContainer);

		final SingleResp bestSingleResp = getBestSingleResp(certificateId, basicOCSPResp);
		if (bestSingleResp == null) {
			return null;
		}

		final OCSPToken ocspToken = new OCSPToken(basicOCSPResp, bestSingleResp, certificatePool);
		ocspToken.setSourceURI(ocspAccessLocation);
		certificateToken.setRevocationToken(ocspToken);
		updateCacheIfRefreshed(certificateId, refresh, ocspToken);
		return ocspToken;
	}

	/**
	 * This method indicates if the {@code OCSPToken} for a given {@code CertificateToken} identified by its {@code CertificateID} should be refreshed or not.
	 *
	 * @param certificateId {@code CertificateID}
	 * @return in the default implementation {@code false} is always returned
	 */
	protected boolean shouldCacheBeRefreshed(final CertificateID certificateId) {
		return false;
	}

	/**
	 * This method allows to update the cache information. Apply only to the implementations handling the cache information like {@see InMemoryCacheOnlineOCSPSource}
	 *
	 * @param certificateId {@code CertificateID}
	 * @param refresh       indicates if the cached {@code OCSPToken} was refreshed or not
	 * @param ocspToken     refreshed {@code OCSPToken}
	 */
	protected void updateCacheIfRefreshed(final CertificateID certificateId, final boolean refresh, final OCSPToken ocspToken) {

	}

	protected SingleResp getBestSingleResp(final CertificateID certificateId, final BasicOCSPResp basicOCSPResp) {

		Date bestUpdate = null;
		SingleResp bestSingleResp = null;
		for (final SingleResp singleResp : basicOCSPResp.getResponses()) {

			if (DSSRevocationUtils.matches(certificateId, singleResp)) {

				final Date thisUpdate = singleResp.getThisUpdate();
				if (bestUpdate == null || thisUpdate.after(bestUpdate)) {

					bestSingleResp = singleResp;
					bestUpdate = thisUpdate;
				}
			}
		}
		return bestSingleResp;
	}

	protected BasicOCSPResp buildBasicOCSPResp(final String ocspAccessLocation, final byte[] ocspRequest, boolean refresh) throws DSSException {

		final byte[] ocspRespBytes = dataLoader.post(ocspAccessLocation, ocspRequest, refresh);
		try {
			final OCSPResp ocspResp = new OCSPResp(ocspRespBytes);
			return (BasicOCSPResp) ocspResp.getResponseObject();
		} catch (NullPointerException e) {
			throw new DSSException("OCSPResp is initialised with a null OCSP response... (and there is no nullity check in the OCSPResp implementation)", e);
		} catch (IOException e) {
			throw new DSSException(e);
		} catch (OCSPException e) {
			throw new DSSException(e);
		}
	}

	protected NonceContainer getNonceContainer() {

		if (ADD_NONCE) {
			return new NonceContainer();
		}
		return null;
	}

	protected void checkNonce(String dssIdAsString, BasicOCSPResp basicOCSPResp, NonceContainer nonceContainer) throws DSSException {

		if (ADD_NONCE) {

			final Extension extension = basicOCSPResp.getExtension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce);
			final DEROctetString receivedNonce = (DEROctetString) extension.getExtnValue();
			if (!receivedNonce.equals(nonceContainer.nonce)) {

				throw new DSSException(
					  "The OCSP request for " + dssIdAsString + " was the victim of replay attack: nonce[sent:" + nonceContainer.nonce + ", received:" + receivedNonce);
			}
		}
	}

	protected byte[] buildOCSPRequest(final CertificateID certificateId, final NonceContainer nonceContainer) throws DSSException {

		try {

			final OCSPReqBuilder ocspReqBuilder = new OCSPReqBuilder();
			ocspReqBuilder.addRequest(certificateId);
			if (nonceContainer != null) {

				final DEROctetString nonce = nonceContainer.nonce;
				final Extension extension = new Extension(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, true, nonce);
				final Extensions extensions = new Extensions(extension);
				ocspReqBuilder.setRequestExtensions(extensions);
			}
			final OCSPReq ocspReq = ocspReqBuilder.build();
			final byte[] ocspReqData = ocspReq.getEncoded();
			return ocspReqData;
		} catch (OCSPException e) {
			throw new DSSException(e);
		} catch (IOException e) {
			throw new DSSException(e);
		}
	}

	/**
	 * Gives back the OCSP URI meta-data found within the given X509 cert.
	 *
	 * @param certificateToken {@code CertificateToken} to use.
	 * @return the OCSP URI, or {@code null} if the extension is not present.
	 * @throws DSSException in the case on any problems
	 */
	public String getAccessLocation(final CertificateToken certificateToken) throws DSSException {

		final byte[] authInfoAccessExtensionValue = certificateToken.getExtensionValue(authorityInfoAccess);
		if (null == authInfoAccessExtensionValue) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("OCSP's URL(s) for {} : there is no authority info access extension!", certificateToken.getAbbreviation());
			}
			return null;
		}
		final ASN1Sequence asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(authInfoAccessExtensionValue);
		final AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(asn1Sequence);
		final AccessDescription[] accessDescriptions = authorityInformationAccess.getAccessDescriptions();
		for (final AccessDescription accessDescription : accessDescriptions) {

			if (!ocspAccessMethod.equals(accessDescription.getAccessMethod())) {
				continue;
			}
			final GeneralName gn = accessDescription.getAccessLocation();
			if (uniformResourceIdentifier != gn.getTagNo()) {
				LOG.warn("Not a uniform resource identifier!");
				continue;
			}
			final DERIA5String str = (DERIA5String) ((DERTaggedObject) gn.toASN1Primitive()).getObject();
			final String accessLocation = str.getString();
			if (LOG.isDebugEnabled()) {
				LOG.debug("OCSP's URL(s) for {} : {}", certificateToken.getAbbreviation(), accessLocation);
			}
			return accessLocation;
		}
		if (LOG.isTraceEnabled()) {
			LOG.trace("OCSP's URL(s) for {} : there is no access location in AIA extension!", certificateToken.getAbbreviation());
		}
		return null;
	}

	@Override
	public boolean isFresh(final RevocationToken revocationToken) {
		return false;
	}
}
