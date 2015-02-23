/*
 * SD-DSS - Digital Signature Services
 *
 * Copyright (C) 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * Developed by: 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
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

package eu.europa.ec.markt.dss.validation102853.crl;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.IssuingDistributionPoint;
import org.bouncycastle.asn1.x509.ReasonFlags;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSASN1Utils;
import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.CertificateToken;
import eu.europa.ec.markt.dss.validation102853.RevocationToken;
import eu.europa.ec.markt.dss.validation102853.loader.Protocol;

import static org.bouncycastle.asn1.x509.DistributionPointName.FULL_NAME;
import static org.bouncycastle.asn1.x509.GeneralName.uniformResourceIdentifier;

/**
 * This is the representation of simple (common) CRL source, this is the base class for all real implementations.
 * <p/>
 *
 * @author Robert Bielecki
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public abstract class CommonCRLSource implements CRLSource {

	private static final Logger LOG = LoggerFactory.getLogger(CommonCRLSource.class);

	/**
	 * Gives back the {@code List} of CRL URI meta-data found within the given X509 certificate.
	 *
	 * @param certificateToken  the X509 certificate
	 * @param preferredProtocol
	 * @param preferredProtocol indicates the preferred protocol to use to retrieve the revocation data
	 * @return the {@code List} of CRL URI, or {@code null} if the extension is not present
	 * @throws DSSException in the case of any {@code Exception}
	 */
	public List<String> getCrlUrl(final CertificateToken certificateToken, final Protocol preferredProtocol) throws DSSException {

		final byte[] crlDistributionPointsBytes = certificateToken.getCRLDistributionPoints();
		if (null == crlDistributionPointsBytes) {
			if (LOG.isTraceEnabled()) {
				LOG.trace("CRL's URL(s) for {} : there is no distribution point(s) extension!", certificateToken.getAbbreviation());
			}
			return null;
		}
		try {

			final List<String> urls = new ArrayList<String>();
			final ASN1Sequence asn1Sequence = DSSASN1Utils.getAsn1SequenceFromDerOctetString(crlDistributionPointsBytes);
			final CRLDistPoint distPoint = CRLDistPoint.getInstance(asn1Sequence);
			final DistributionPoint[] distributionPoints = distPoint.getDistributionPoints();
			for (final DistributionPoint distributionPoint : distributionPoints) {

				final DistributionPointName distributionPointName = distributionPoint.getDistributionPoint();
				if (FULL_NAME != distributionPointName.getType()) {
					LOG.warn("'nameRelativeToCRLIssuer': not supported!");
					continue;
				}
				final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
				final GeneralName[] names = generalNames.getNames();
				for (final GeneralName name : names) {

					if (uniformResourceIdentifier != name.getTagNo()) {

						LOG.warn("Not a uniform resource identifier!");
						continue;
					}
					ASN1Primitive asn1Primitive = name.toASN1Primitive();
					if (asn1Primitive instanceof DERTaggedObject) {

						final DERTaggedObject taggedObject = (DERTaggedObject) asn1Primitive;
						asn1Primitive = taggedObject.getObject();
					}
					final DERIA5String derStr = DERIA5String.getInstance(asn1Primitive);
					final String urlStr = derStr.getString();
					urls.add(urlStr);
				}
			}
			prioritize(urls, preferredProtocol);
			if (LOG.isTraceEnabled()) {
				LOG.trace("CRL's URL for {} : {}", certificateToken.getAbbreviation(), urls);
			}
			return urls;
		} catch (Exception e) {
			if (e instanceof DSSException) {
				throw (DSSException) e;
			}
			throw new DSSException(e);
		}
	}

	/**
	 * if {@code preferredProtocol} is set then the list of urls is prioritize.
	 * NOTE: This is not standard conformant! However in the major number of cases LDAP is much slower then HTTP!
	 *
	 * @param urls              {@code List} of urls to prioritize
	 * @param preferredProtocol indicates the preferred protocol to use to retrieve the revocation data
	 */
	private void prioritize(final List<String> urls, final Protocol preferredProtocol) {

		if (preferredProtocol != null) {

			final List<String> priorityUrls = new ArrayList<String>();
			for (final String url : urls) {
				if (preferredProtocol.isTheSame(url)) {
					priorityUrls.add(url);
				}
			}
			urls.removeAll(priorityUrls);
			for (int ii = priorityUrls.size() - 1; ii >= 0; ii--) {
				urls.add(0, priorityUrls.get(ii));
			}
		}
	}

	/**
	 * This method verifies: the signature of the CRL, the key usage of its signing certificate and the coherence between the subject names of the CRL signing certificate and the
	 * issuer name of the certificate for which the verification of the revocation data is carried out. A dedicated object based on {@code CRLValidity} is created and accordingly
	 * updated.
	 *
	 * @param x509CRL         {@code X509CRL} to be verified (cannot be null)
	 * @param issuerToken     {@code CertificateToken} used to sign the {@code X509CRL} (cannot be null)  @return {@code CRLValidity}
	 * @param dpUrlStringList {@code List} of {@code String} representation of the DP's url
	 */
	protected CRLValidity isValidCRL(final X509CRL x509CRL, final CertificateToken issuerToken, final List<String> dpUrlStringList) {

		final CRLValidity crlValidity = new CRLValidity();
		crlValidity.x509CRL = x509CRL;

		final X500Principal x509CRLIssuerX500Principal = DSSUtils.getX500Principal(x509CRL.getIssuerX500Principal());
		final X500Principal issuerTokenSubjectX500Principal = DSSUtils.getX500Principal(issuerToken.getSubjectX500Principal());
		if (x509CRLIssuerX500Principal.equals(issuerTokenSubjectX500Principal)) {

			crlValidity.issuerX509PrincipalMatches = true;
		}
		checkCriticalExtensions(x509CRL, dpUrlStringList, crlValidity);
		checkSignatureValue(x509CRL, issuerToken, crlValidity);
		if (crlValidity.signatureIntact) {

			crlValidity.crlSignKeyUsage = issuerToken.hasCRLSignKeyUsage();
		}
		return crlValidity;
	}

	private void checkSignatureValue(final X509CRL x509CRL, final CertificateToken issuerToken, final CRLValidity crlValidity) {

		try {

			x509CRL.verify(issuerToken.getPublicKey());
			crlValidity.signatureIntact = true;
			crlValidity.issuerToken = issuerToken;
		} catch (InvalidKeyException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (CRLException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (NoSuchAlgorithmException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (SignatureException e) {
			crlValidity.signatureInvalidityReason = e.getClass().getSimpleName() + " - " + e.getMessage();
		} catch (NoSuchProviderException e) {
			throw new DSSException(e);
		}
	}

	private void checkCriticalExtensions(final X509CRL x509CRL, final List<String> dpUrlStringList, final CRLValidity crlValidity) {

		final Set<String> criticalExtensionOIDs = x509CRL.getCriticalExtensionOIDs();
		if (criticalExtensionOIDs == null || criticalExtensionOIDs.size() == 0) {
			crlValidity.unknownCriticalExtension = false;
			return;
		}
		final String issuingDistributionPointOid = Extension.issuingDistributionPoint.toString();
		for (final String criticalExtensionOID : criticalExtensionOIDs) {

			if (issuingDistributionPointOid.equals(criticalExtensionOID)) {

				final byte[] extensionValue = x509CRL.getExtensionValue(issuingDistributionPointOid);
				final ASN1OctetString asn1OctetStringExtensionValue = ASN1OctetString.getInstance(extensionValue);
				final IssuingDistributionPoint issuingDistributionPoint = IssuingDistributionPoint.getInstance(asn1OctetStringExtensionValue.getOctets());
				final boolean onlyAttributeCerts = issuingDistributionPoint.onlyContainsAttributeCerts();
				final boolean onlyCaCerts = issuingDistributionPoint.onlyContainsCACerts();
				final boolean onlyUserCerts = issuingDistributionPoint.onlyContainsUserCerts();
				final boolean indirectCrl = issuingDistributionPoint.isIndirectCRL();
				final ReasonFlags reasonFlags = issuingDistributionPoint.getOnlySomeReasons();
				final DistributionPointName distributionPointName = issuingDistributionPoint.getDistributionPoint();

				boolean urlFound = false;
				if (FULL_NAME == distributionPointName.getType()) {

					final GeneralNames generalNames = (GeneralNames) distributionPointName.getName();
					if (generalNames != null) {

						final GeneralName[] names = generalNames.getNames();
						if (names != null && names.length > 0) {
							for (final GeneralName generalName : names) {
								if (uniformResourceIdentifier == generalName.getTagNo()) {

									final String name = generalName.getName().toString();
									if (DSSUtils.isNotEmpty(dpUrlStringList) && dpUrlStringList.contains(name)) {
										urlFound = true;
									}
								}
							}
						}
					}
				}
				if (!(onlyAttributeCerts && onlyCaCerts && onlyUserCerts && indirectCrl) && reasonFlags == null && urlFound) {
					crlValidity.unknownCriticalExtension = false;
				}
				continue;
			}
			crlValidity.unknownCriticalExtension = true;
		}
	}

	@Override
	public boolean isFresh(final RevocationToken revocationToken) {
		return false;
	}
}