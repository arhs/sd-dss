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

package eu.europa.ec.markt.dss.parameter;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.exception.DSSNullException;

public class BLevelParameters implements Serializable {

	/**
	 * This variable indicates if the Baseline profile's trust anchor policy shall be followed:
	 * ETSI TS 103 171 V2.1.1 (2012-03)
	 * 6.2.1 Placement of the signing certificate
	 * ../..
	 * it is advised to include at least the unavailable intermediary certificates up to but not including the CAs present in the TSLs,
	 * ../..
	 * This rule applies as follows: when -B level is constructed the trust anchor is not included, when -LT level is constructed the trust anchor is included.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are included when -B level is constructed.
	 */
	private boolean trustAnchorBPPolicy = true;

	private Date signingDate = new Date();

	/**
	 * The digest method used to create the digest of the signer's certificate.
	 */
	private DigestAlgorithm signingCertificateDigestMethod = DigestAlgorithm.SHA1;

	private List<String> claimedSignerRoles;
	private List<CertifiedRole> certifiedSignerRoles;

	private Policy signaturePolicy;

	// TODO: move to a CAdES-B specific parameter class
	private String contentIdentifierPrefix;
	private String contentIdentifierSuffix;

	private List<CommitmentTypeIndication> commitmentTypeIndication;
	private SignerLocation signerLocation;
	private String contentHintsType;
	private String contentHintsDescription;

	/**
	 * Default constructor
	 */
	BLevelParameters() {
	}

	/**
	 * Copy constructor.
	 *
	 * @param source {@code BLevelParameters} source parameters
	 */
	BLevelParameters(final BLevelParameters source) {

		if (source == null) {
			throw new DSSNullException(BLevelParameters.class);
		}
		signingCertificateDigestMethod = source.signingCertificateDigestMethod;
		this.trustAnchorBPPolicy = source.trustAnchorBPPolicy;
		if (source.signaturePolicy != null) {
			this.signaturePolicy = new Policy(source.signaturePolicy);
		}
		this.signingDate = source.signingDate;
		if (source.claimedSignerRoles != null) {
			this.claimedSignerRoles = new ArrayList<String>(source.claimedSignerRoles);
		}
		if (source.certifiedSignerRoles != null) {
			this.certifiedSignerRoles = new ArrayList<CertifiedRole>(source.certifiedSignerRoles);
		}

		this.contentHintsType = source.contentHintsType;
		this.contentHintsDescription = source.contentHintsDescription;

		this.contentIdentifierPrefix = source.contentIdentifierPrefix;
		this.contentIdentifierSuffix = source.contentIdentifierSuffix;

		if (source.commitmentTypeIndication != null) {
			this.commitmentTypeIndication = new ArrayList<CommitmentTypeIndication>(source.commitmentTypeIndication);
		}
		if (source.signerLocation != null) {
			this.signerLocation = new SignerLocation(source.signerLocation);
		}
	}

	/**
	 * @return indicates the trust anchor policy shall be used when creating -B and -LT levels
	 */
	public boolean isTrustAnchorBPPolicy() {
		return trustAnchorBPPolicy;
	}

	/**
	 * Allows to set the trust anchor policy to use when creating -B and -LT levels.
	 * NOTE: when trust anchor baseline profile policy is defined only the certificates previous to the trust anchor are included when building -B level.
	 *
	 * @param trustAnchorBPPolicy {@code boolean}
	 */
	public void setTrustAnchorBPPolicy(boolean trustAnchorBPPolicy) {
		this.trustAnchorBPPolicy = trustAnchorBPPolicy;
	}

	/**
	 * @return the signature policy to use during the signature creation process
	 */
	public Policy getSignaturePolicy() {

		return signaturePolicy;
	}

	/**
	 * This setter allows to indicate the signature policy to use.
	 *
	 * @param signaturePolicy signature policy to use
	 */
	public void setSignaturePolicy(final Policy signaturePolicy) {

		this.signaturePolicy = signaturePolicy;
	}

	/**
	 * THIS VALUE WILL BE SET AUTOMATICALLY IF LEFT BLANK
	 * <p/>
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * <p/>
	 * 5.10.2 content-identifier Attribute
	 * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
	 * later required to that content; for example, in the content-reference attribute in other signed data sent later. The
	 * content-identifier shall be a signed attribute.
	 * content-identifier attribute type values for the ES have an ASN.1 type ContentIdentifier, as defined in
	 * ESS (RFC 2634 [5]).
	 * <p/>
	 * The minimal content-identifier attribute should contain a concatenation of user-specific identification
	 * information (such as a user name or public keying material identification information), a GeneralizedTime string,
	 * and a random number.
	 *
	 * @return
	 */
	public String getContentIdentifierSuffix() {
		return contentIdentifierSuffix;
	}

	/**
	 * @param contentIdentifierSuffix
	 * @see #getContentIdentifierSuffix()
	 */
	public void setContentIdentifierSuffix(String contentIdentifierSuffix) {
		this.contentIdentifierSuffix = contentIdentifierSuffix;
	}

	public String getContentHintsType() {
		return contentHintsType;
	}

	public void setContentHintsType(String contentHintsType) {
		this.contentHintsType = contentHintsType;
	}

	public String getContentHintsDescription() {
		return contentHintsDescription;
	}

	public void setContentHintsDescription(String contentHintsDescription) {
		this.contentHintsDescription = contentHintsDescription;
	}

	/**
	 * Get the signing date
	 *
	 * @return the value
	 */
	public Date getSigningDate() {
		return signingDate;
	}

	/**
	 * Set the signing date
	 *
	 * @param signingDate the value
	 */
	public void setSigningDate(final Date signingDate) {

		this.signingDate = signingDate;
	}

	/**
	 * See {@link #setSigningCertificateDigestMethod(DigestAlgorithm).
	 *
	 * @return
	 */
	public DigestAlgorithm getSigningCertificateDigestMethod() {
		return signingCertificateDigestMethod;
	}

	/**
	 * This property is a part of the standard:<br>
	 * 7.2.2 The SigningCertificate element (101 903 V1.4.2 (2010-12) XAdES)<br>
	 * The digest method indicates the digest algorithm to be used to calculate the CertDigest element that contains the
	 * digest for each certificate referenced in the sequence.
	 *
	 * @param signingCertificateDigestMethod
	 */
	public void setSigningCertificateDigestMethod(final DigestAlgorithm signingCertificateDigestMethod) {
		this.signingCertificateDigestMethod = signingCertificateDigestMethod;
	}

	/**
	 * Get claimed role
	 *
	 * @return the value
	 */
	public List<String> getClaimedSignerRoles() {
		return claimedSignerRoles;
	}

	/**
	 * Adds a claimed signer role
	 *
	 * @param claimedSignerRole the value
	 */
	public void addClaimedSignerRole(final String claimedSignerRole) {

		final boolean empty = DSSUtils.isEmpty(claimedSignerRole);
		if (empty) {

			throw new DSSNullException(String.class, "claimedSignerRole");
		}
		if (claimedSignerRoles == null) {

			claimedSignerRoles = new ArrayList<String>();
		}
		claimedSignerRoles.add(claimedSignerRole);
	}

	public List<CertifiedRole> getCertifiedSignerRoles() {
		return certifiedSignerRoles;
	}

	/**
	 * Adds a certified signer role (attribute certificate)
	 *
	 * @param attributeCertificateBase64Encoded {@code String}
	 * @param encoding                          {@code String} example: Encoding="http://uri.etsi.org/01903/v1.2.2#DER"
	 */
	public void addCertifiedSignerRole(final String attributeCertificateBase64Encoded, String encoding) {

		if (certifiedSignerRoles == null) {
			certifiedSignerRoles = new ArrayList<CertifiedRole>();
		}
		certifiedSignerRoles.add(new CertifiedRole(attributeCertificateBase64Encoded, encoding));
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * <p/>
	 * 5.11.1 commitment-type-indication Attribute
	 * There may be situations where a signer wants to explicitly indicate to a verifier that by signing the data, it illustrates a
	 * type of commitment on behalf of the signer. The commitment-type-indication attribute conveys such
	 * information.
	 */
	public List<CommitmentTypeIndication> getCommitmentTypeIndications() {
		return commitmentTypeIndication;
	}

	public void setCommitmentTypeIndications(final List<CommitmentTypeIndication> commitmentTypeIndication) {
		this.commitmentTypeIndication = commitmentTypeIndication;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * <p/>
	 * 5.10.2 content-identifier Attribute
	 * The content-identifier attribute provides an identifier for the signed content, for use when a reference may be
	 * later required to that content; for example, in the content-reference attribute in other signed data sent later. The
	 * content-identifier shall be a signed attribute.
	 * content-identifier attribute type values for the ES have an ASN.1 type ContentIdentifier, as defined in
	 * ESS (RFC 2634 [5]).
	 * <p/>
	 * The minimal content-identifier attribute should contain a concatenation of user-specific identification
	 * information (such as a user name or public keying material identification information), a GeneralizedTime string,
	 * and a random number.
	 *
	 * @return
	 */
	public String getContentIdentifierPrefix() {
		return contentIdentifierPrefix;
	}

	/**
	 * @param contentIdentifierPrefix
	 * @see #getContentIdentifierPrefix()
	 */
	public void setContentIdentifierPrefix(String contentIdentifierPrefix) {
		this.contentIdentifierPrefix = contentIdentifierPrefix;
	}

	/**
	 * ETSI TS 101 733 V2.2.1 (2013-04)
	 * <p/>
	 * 5.11.2 signer-location Attribute
	 * The signer-location attribute specifies a mnemonic for an address associated with the signer at a particular
	 * geographical (e.g. city) location. The mnemonic is registered in the country in which the signer is located and is used in
	 * the provision of the Public Telegram Service (according to Recommendation ITU-T F.1 [11]).
	 * The signer-location attribute shall be a signed attribute.
	 * <p/>
	 * The following object identifier identifies the signer-location attribute:
	 * id-aa-ets-signerLocation OBJECT IDENTIFIER ::= { iso(1) member-body(2)
	 * us(840) rsadsi(113549) pkcs(1) pkcs-9(9) smime(16) id-aa(2) 17}
	 * Signer-location attribute values have ASN.1 type SignerLocation:
	 * SignerLocation ::= SEQUENCE { -- at least one of the following shall be present:
	 * countryName [0] DirectoryString OPTIONAL,
	 * -- As used to name a Country in X.500
	 * localityName [1] DirectoryString OPTIONAL,
	 * -- As used to name a locality in X.500
	 * postalAdddress [2] PostalAddress OPTIONAL }
	 * PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
	 *
	 * @return the location
	 */
	public SignerLocation getSignerLocation() {
		return signerLocation;
	}

	/**
	 * @param signerLocation the location to set
	 */
	public void setSignerLocation(final SignerLocation signerLocation) {
		this.signerLocation = signerLocation;
	}

	/**
	 * SignerLocation ::= SEQUENCE { -- at least one of the following shall be present
	 * countryName [0] DirectoryString OPTIONAL,
	 * -- As used to name a Country in X.500
	 * localityName [1] DirectoryString OPTIONAL,
	 * -- As used to name a locality in X.500
	 * postalAdddress [2] PostalAddress OPTIONAL }
	 * PostalAddress ::= SEQUENCE SIZE(1..6) OF DirectoryString
	 */
	public static class SignerLocation implements Serializable {

		private String country;

		private String locality;

		private List<String> postalAddress = new ArrayList<String>(6);

		/**
		 * From XAdES standard:
		 */

		private String postalCode;
		private String city;
		private String stateOrProvince;

		public SignerLocation() {
		}

		public SignerLocation(final SignerLocation signerLocation) {

			country = signerLocation.country;
			locality = signerLocation.locality;
			if (signerLocation.postalAddress != null) {

				postalAddress = new ArrayList<String>(signerLocation.postalAddress);
			}
			postalCode = signerLocation.postalCode;
			city = signerLocation.city;
			stateOrProvince = signerLocation.stateOrProvince;
		}

		public String getCountry() {
			return country;
		}

		public void setCountry(final String country) {
			this.country = country;
		}

		public String getLocality() {
			return locality;
		}

		public void setLocality(final String locality) {
			this.locality = locality;
		}

		public List<String> getPostalAddress() {
			return postalAddress;
		}

		public void setPostalAddress(final List<String> postalAddress) {
			this.postalAddress = postalAddress;
		}

		public String getPostalCode() {
			return postalCode;
		}

		public void setPostalCode(String postalCode) {
			this.postalCode = postalCode;
		}

		public String getCity() {
			return city;
		}

		public void setCity(String city) {
			this.city = city;
		}

		public String getStateOrProvince() {
			return stateOrProvince;
		}

		public void setStateOrProvince(String stateOrProvince) {
			this.stateOrProvince = stateOrProvince;
		}

		/**
		 * Adds an address item to the complete address.
		 *
		 * @param addressItem
		 */
		public void addPostalAddress(final String addressItem) {

			if (postalAddress != null) {

				postalAddress = new ArrayList<String>(6);
			}
			postalAddress.add(addressItem);
		}
	}

	/**
	 * This inner class allows to define the signature policy.
	 */
	public static class Policy implements Serializable {

		private String id;

		private DigestAlgorithm digestAlgorithm;

		private byte[] digestValue;

		public Policy(final Policy policy) {

			id = policy.id;
			digestAlgorithm = policy.digestAlgorithm;
			digestValue = Arrays.copyOf(policy.digestValue, policy.digestValue.length);
		}

		/**
		 * Get the signature policy (EPES)
		 *
		 * @return
		 */
		public String getId() {
			return id;
		}

		/**
		 * Set the signature policy (EPES)
		 *
		 * @param id
		 */
		public void setId(final String id) {
			this.id = id;
		}

		/**
		 * Return the hash algorithm for the signature policy
		 *
		 * @return
		 */
		public DigestAlgorithm getDigestAlgorithm() {
			return digestAlgorithm;
		}

		/**
		 * Set the hash algorithm for the explicit signature policy
		 *
		 * @param digestAlgorithm
		 */
		public void setDigestAlgorithm(final DigestAlgorithm digestAlgorithm) {
			this.digestAlgorithm = digestAlgorithm;
		}

		/**
		 * Get the hash value of the explicit signature policy
		 *
		 * @return
		 */
		public byte[] getDigestValue() {
			return digestValue;
		}

		/**
		 * Set the hash value of implicit signature policy
		 *
		 * @param digestValue
		 */
		public void setDigestValue(final byte[] digestValue) {
			this.digestValue = digestValue;
		}
	}

	public static class CertifiedRole implements Serializable {

		protected String attributeCertificateBase64Encoded;
		protected String encoding;

		public CertifiedRole(final String attributeCertificateBase64Encoded, final String encoding) {

			this.attributeCertificateBase64Encoded = attributeCertificateBase64Encoded;
			this.encoding = encoding;
		}

		public String getAttributeCertificateBase64Encoded() {
			return attributeCertificateBase64Encoded;
		}

		public void setAttributeCertificateBase64Encoded(final String attributeCertificateBase64Encoded) {
			this.attributeCertificateBase64Encoded = attributeCertificateBase64Encoded;
		}

		public String getEncoding() {
			return encoding;
		}

		public void setEncoding(final String encoding) {
			this.encoding = encoding;
		}
	}

	public static class CommitmentTypeIndication {

		protected String identifier;
		protected String description;
		protected List<String> documentationReferences;

		protected List<String> objectReferences;

		public CommitmentTypeIndication(final String identifier) {
			this.identifier = identifier;
		}

		public String getIdentifier() {
			return identifier;
		}

		public void setIdentifier(final String identifier) {
			this.identifier = identifier;
		}

		public String getDescription() {
			return description;
		}

		public void setDescription(final String description) {
			this.description = description;
		}

		public void addDocumentationReference(final String documentationReference) {

			if (documentationReferences == null) {
				documentationReferences = new ArrayList<String>();
			}
			documentationReferences.add(documentationReference);
		}

		public List<String> getDocumentationReferences() {
			return documentationReferences;
		}

		public void addObjectReference(final String objectReference) {

			if (objectReferences == null) {
				objectReferences = new ArrayList<String>();
			}
			objectReferences.add(objectReference);
		}

		public List<String> getObjectReferences() {
			return objectReferences;
		}
	}
}
