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

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;

import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.exception.DSSNullException;
import eu.europa.ec.markt.dss.validation102853.certificate.CertificateSourceType;
import eu.europa.ec.markt.dss.validation102853.condition.ServiceInfo;
import eu.europa.ec.markt.dss.validation102853.crl.CRLSource;
import eu.europa.ec.markt.dss.validation102853.crl.CRLToken;
import eu.europa.ec.markt.dss.validation102853.loader.DataLoader;
import eu.europa.ec.markt.dss.validation102853.ocsp.OCSPSource;

/**
 * During the validation of a signature, the software retrieves different X509 artifacts like Certificate, CRL and OCSP Response. The SignatureValidationContext is a "cache" for
 * one validation request that contains every object retrieved so far.
 * <p/>
 * The validate method is multi-threaded, using an CachedThreadPool from ExecutorService, to parallelize fetching of the certificates from AIA and of the revocation information
 * from online sources.
 * <p/>
 * NOTE: An instance of this class can be used only once!
 *
 * @author Robert Bielecki
 * @version $Revision: 1839 $ - $Date: 2013-04-04 17:40:51 +0200 (Thu, 04 Apr 2013) $
 */

public class SignatureValidationContext implements ValidationContext {

	private static final Logger LOG = LoggerFactory.getLogger(SignatureValidationContext.class);

	// just for convenience
	private final boolean logEnabled = LOG.isTraceEnabled();

	/**
	 * The delay used to wait for the thread execution in the loop
	 */
	private static final int WAIT_DELAY = 5;

	/**
	 * Each unit is approximately 5 seconds
	 */
	public static int MAX_TIMEOUT = 5;

	private final Map<CertificateToken, Boolean> processedCertificates = new ConcurrentHashMap<CertificateToken, Boolean>();
	private final Map<RevocationToken, Boolean> processedRevocations = new ConcurrentHashMap<RevocationToken, Boolean>();
	private final Map<TimestampToken, Boolean> processedTimestamps = new ConcurrentHashMap<TimestampToken, Boolean>();

	private final TokensToProcess tokensToProcess = new TokensToProcess();

	/**
	 * This variable indicates the number of threads being used
	 */
	int threadCount = 0;

	/**
	 * This variable indicates if the instance has been already used
	 */
	private Boolean validated = false;

	/**
	 * The data loader used to access AIA certificate source.
	 */
	private DataLoader dataLoader;

	/**
	 * The certificate pool which encapsulates all certificates used during the validation process and extracted from all used sources
	 */
	protected CertificatePool validationCertificatePool;

	// External OCSP source.
	private OCSPSource ocspSource;

	// External CRL source.
	private CRLSource crlSource;

	// OCSP from the signature.
	private OCSPSource signatureOCSPSource;

	// CRLs from the signature.
	private CRLSource signatureCRLSource;

	/**
	 * This is the time at what the validation is carried out. It is used only for test purpose.
	 */
	protected Date currentTime = new Date();

	/**
	 * This variable :
	 */
	protected ExecutorService executorService;

	private int threshold = 0;
	private int max_timeout = 0;

	/**
	 * This constructor is used when a signature need to be validated.
	 *
	 * @param certificateVerifier       The certificates verifier (eg: using the TSL as list of trusted certificates).
	 * @param validationCertificatePool The pool of certificates used during the validation process
	 */
	public SignatureValidationContext(final CertificateVerifier certificateVerifier, final CertificatePool validationCertificatePool) {

		if (certificateVerifier == null) {
			throw new DSSNullException(CertificateVerifier.class);
		}
		if (validationCertificatePool == null) {
			throw new DSSNullException(CertificatePool.class);
		}
		this.validationCertificatePool = validationCertificatePool;
		this.crlSource = certificateVerifier.getCrlSource();
		this.ocspSource = certificateVerifier.getOcspSource();
		this.dataLoader = certificateVerifier.getDataLoader();
		this.signatureCRLSource = certificateVerifier.getSignatureCRLSource();
		this.signatureOCSPSource = certificateVerifier.getSignatureOCSPSource();
	}

	@Override
	public ExecutorService getExecutorService() {
		return executorService;
	}

	@Override
	public void setExecutorService(final ExecutorService executorService) {
		this.executorService = executorService;
	}

	private ExecutorService provideExecutorService() {

		if (executorService == null) {
			executorService = Executors.newCachedThreadPool();
		}
		return executorService;
	}

	@Override
	public Date getCurrentTime() {
		return currentTime;
	}

	@Override
	public void setCurrentTime(final Date currentTime) throws DSSException {

		if (currentTime == null) {
			throw new DSSNullException(Date.class, "currentTime");
		}
		this.currentTime = currentTime;
	}

	/**
	 * This method returns the issuer certificate (the certificate which was used to sign the token) of the given token.
	 *
	 * @param token the token for which the issuer must be obtained.
	 * @return the issuer certificate token of the given token or null if not found.
	 * @throws eu.europa.ec.markt.dss.exception.DSSException
	 */
	private CertificateToken getIssuerCertificate(final Token token) throws DSSException {

		if (logEnabled) {
			LOG.trace(" > Get issuer for: {}", token.getAbbreviation());
		}
		if (token.isTrusted()) {
			if (logEnabled) {
				LOG.trace(" > Token is trusted: {}", token.getAbbreviation());
			}
			return null; // When the token is trusted the check of the issuer token is not needed so null is returned. Only a certificate token can be trusted.
		}
		if (token.getIssuerToken() != null) {

			if (logEnabled) {
				LOG.trace(" > Token has already an issuer: {}", token.getAbbreviation());
			}
			/**
			 * The signer's certificate have been found already. This can happen in the case of:<br>
			 * - multiple signatures that use the same certificate,<br>
			 * - OCSPRespTokens (the issuer certificate is known from the beginning)
			 */
			return token.getIssuerToken();
		}
		final X500Principal issuerX500Principal = token.getIssuerX500Principal();
		CertificateToken issuerCertificateToken = getIssuerFromPool(token, issuerX500Principal);

		if (issuerCertificateToken == null && token instanceof CertificateToken) {
			issuerCertificateToken = getIssuerFromAIA((CertificateToken) token);
		}
		if (issuerCertificateToken == null) {

			if (logEnabled) {
				LOG.trace(" > Issuer not found: {}", token.getAbbreviation());
			}
			token.extraInfo().infoTheSigningCertNotFound();
		}
		if (issuerCertificateToken != null && !issuerCertificateToken.isTrusted() && !issuerCertificateToken.isSelfSigned()) {
			getIssuerCertificate(issuerCertificateToken); // The full chain is retrieved for each certificate
		}
		return issuerCertificateToken;
	}

	/**
	 * Get the issuer's certificate from Authority Information Access through id-ad-caIssuers extension.
	 *
	 * @param token {@code CertificateToken} for which the issuer is sought.
	 * @return {@code CertificateToken} representing the issuer certificate or null.
	 */
	private CertificateToken getIssuerFromAIA(final CertificateToken token) {

		final X509Certificate issuerCert;
		try {

			LOG.debug("Retrieving {} certificate's issuer using AIA.", token.getAbbreviation());
			issuerCert = DSSUtils.loadIssuerCertificate(token.getCertificate(), dataLoader);
			if (issuerCert != null) {

				final CertificateToken issuerCertToken = validationCertificatePool.getInstance(issuerCert, CertificateSourceType.AIA);
				if (token.isSignedBy(issuerCertToken)) {

					if (LOG.isDebugEnabled()) {
						LOG.debug(" > Issuer found in AIA: {}", token.getAbbreviation());
					}
					return issuerCertToken;
				}
				LOG.warn("The retrieved certificate using AIA does not sign the certificate {}!", token.getAbbreviation());
			} else {
				LOG.warn("The issuer certificate cannot be loaded using AIA!");
			}
		} catch (DSSException e) {
			LOG.error(e.getMessage());
		}
		return null;
	}

	/**
	 * This function retrieves the issuer certificate from the validation pool (this pool should contain trusted certificates). The check is made if the token is well signed by
	 * the retrieved certificate.
	 *
	 * @param token               token for which the issuer have to be found
	 * @param issuerX500Principal issuer's subject distinguished name
	 * @return the corresponding {@code CertificateToken} or null if not found
	 */
	private CertificateToken getIssuerFromPool(final Token token, final X500Principal issuerX500Principal) {

		final List<CertificateToken> issuerCertList = validationCertificatePool.get(issuerX500Principal);
		for (final CertificateToken issuerCertToken : issuerCertList) {

			// We keep the first issuer that signs the certificate
			if (token.isSignedBy(issuerCertToken)) {

				if (logEnabled) {
					LOG.trace(" > Issuer found in the validation pool: {}", token.getAbbreviation());
				}
				return issuerCertToken;
			}
		}
		return null;
	}

	@Override
	public void addCertificateTokenForVerification(final CertificateToken certificateToken) {

		if (tokensToProcess.put(certificateToken)) {

			final Boolean added = processedCertificates.put(certificateToken, true);
			if (logEnabled) {
				if (added == null) {
					LOG.trace("CertificateToken added to processedCertificates: {} ", certificateToken.getAbbreviation());
				} else {
					LOG.trace("CertificateToken already present processedCertificates: {} ", certificateToken.getAbbreviation());
				}
			}
		}
	}

	@Override
	public void addRevocationTokenForVerification(final RevocationToken revocationToken) {

		if (tokensToProcess.put(revocationToken)) {

			final Boolean added = processedRevocations.put(revocationToken, true);
			if (logEnabled) {
				if (added == null) {
					LOG.trace("RevocationToken added to processedRevocations: {} ", revocationToken.getAbbreviation());
				} else {
					LOG.trace("RevocationToken already present processedRevocations: {} ", revocationToken.getAbbreviation());
				}
			}
		}
	}

	@Override
	public void addTimestampTokenForVerification(final TimestampToken timestampToken) {

		if (tokensToProcess.put(timestampToken)) {

			final Boolean added = processedTimestamps.put(timestampToken, true);
			if (logEnabled) {
				if (added == null) {
					LOG.trace("TimestampToken added to processedTimestamps: {} ", timestampToken.getAbbreviation());
				} else {
					LOG.trace("TimestampToken already present processedTimestamps: {} ", timestampToken.getAbbreviation());
				}
			}
		}
	}

	@Override
	public void validate() throws DSSException {

		canValidate();
		Token token = tokensToProcess.get();
		do {
			if (token != null) {
				addNewTask(token);
				token = null;
			}
			awaitTermination();
		} while (threadCount != 0 || (token = tokensToProcess.get()) != null);
		finalizeValidation(executorService);
	}

	private void canValidate() {

		synchronized (validated) {
			if (validated) {
				throw new DSSException("The instance {" + this + "} has been validated!");
			}
			validated = true;
		}
	}

	private void awaitTermination() {

		sleep();
		threshold++;
		if (threshold > 1000) {

			LOG.warn("{} active threads", threadCount);
			max_timeout++;
			if (max_timeout == MAX_TIMEOUT) {
				throw new DSSException("Operation aborted, the retrieval of the validation data takes too long!");
			}
			threshold = 0;
		}
	}

	private void sleep() {

		try {

			Thread.sleep(WAIT_DELAY);
		} catch (InterruptedException e) {
			throw new DSSException(e);
		}
	}

	private void addNewTask(final Token token) {

		try {

			final Task task = new Task(token);
			provideExecutorService().submit(task);
			threadCount++;
		} catch (RejectedExecutionException e) {
			LOG.error(e.getMessage(), e);
			throw new DSSException(e);
		}
	}

	private void finalizeValidation(final ExecutorService executorService) {

		try {

			LOG.debug(">>> Multithreaded validation ***DONE***");
			if (executorService == null) {
				return;
			}
			executorService.shutdown();
			final boolean completedProperly = executorService.awaitTermination(WAIT_DELAY, TimeUnit.SECONDS);
			if (!completedProperly) {
				LOG.warn("Timeout: The validation was interrupted!");
			}
		} catch (InterruptedException e) {
			throw new DSSException(e);
		}
	}

	class Task implements Runnable {

		private final Token token;

		public Task(final Token token) {
			this.token = token;
		}

		@Override
		public void run() {

			if (LOG.isDebugEnabled()) {
				LOG.debug(">>> Start multithreaded processing: token-id: {}", token.getAbbreviation());
			}
			final CertificateToken issuerCertToken = getIssuerCertificate(token); // Gets the issuer certificate of the Token and checks its signature
			if (issuerCertToken != null) {
				addCertificateTokenForVerification(issuerCertToken);
			}
			if (token instanceof CertificateToken) {

				final CertificateToken certificateToken = (CertificateToken) token;
				final RevocationToken currentRevocationToken = certificateToken.getRevocationToken();
				if (currentRevocationToken != null) {

					if (currentRevocationToken instanceof OCSPToken && ocspSource != null) {
						if (ocspSource.isFresh(currentRevocationToken)) {
							LOG.debug("OCSP revocation data for the certificate {} is considered as fresh", certificateToken.getAbbreviation());
							return;
						}
					} else if (currentRevocationToken instanceof CRLToken && crlSource != null) {
						if (crlSource.isFresh(currentRevocationToken)) {
							LOG.debug("CRL revocation data for the certificate {} is considered as fresh", certificateToken.getAbbreviation());
							return;
						}
					}
				}
				final RevocationToken revocationToken = getRevocationData(certificateToken);
				addRevocationTokenForVerification(revocationToken);
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug(">>> Multithreaded processing finished: token-id: {}", token.getAbbreviation());
			}
			threadCount--;
		}
	}

	/**
	 * Retrieves the revocation data from signature (if exists) or from the online sources. The issuer certificate must be provided, the underlining library (bouncy castle) needs
	 * it to build the request. This feature has an impact on the multi-threaded data retrieval.
	 *
	 * @param certToken
	 * @return
	 */
	private RevocationToken getRevocationData(final CertificateToken certToken) {

		if (logEnabled) {
			LOG.trace(" > Retrieve revocation data for: {}", certToken.getAbbreviation());
		}
		if (certToken.isSelfSigned() || certToken.isTrusted() || certToken.getIssuerToken() == null) {

			// It is not possible to check the revocation data without its signing certificate;
			// This check is not needed for the trust anchor.
			if (logEnabled) {
				LOG.trace(" > Certificate is self-signed or trusted or there is no issuer: {}", certToken.getAbbreviation());
			}
			return null;
		}

		if (certToken.isOCSPSigning() && certToken.hasIdPkixOcspNoCheckExtension()) {

			certToken.extraInfo().infoOCSPCheckNotNeeded();
			if (logEnabled) {
				LOG.trace(" > Certificate is ocsp-signing and has id-pkix-ocsp-no-check extension : {}", certToken.getAbbreviation());
			}
			return null;
		}

		boolean checkOnLine = shouldCheckOnLine(certToken);
		if (logEnabled) {
			LOG.trace(" > Should check revocation data online: {} / {}", checkOnLine, certToken.getAbbreviation());
		}
		if (checkOnLine) {

			final OCSPAndCRLCertificateVerifier onlineVerifier = new OCSPAndCRLCertificateVerifier(crlSource, ocspSource, validationCertificatePool);
			final RevocationToken revocationToken = onlineVerifier.check(certToken);
			if (revocationToken != null) {
				if (logEnabled) {
					LOG.trace(" > Revocation data: {} found online for: {}", revocationToken.getAbbreviation(), certToken.getAbbreviation());
				}
				return revocationToken;
			}
		}
		final OCSPAndCRLCertificateVerifier offlineVerifier = new OCSPAndCRLCertificateVerifier(signatureCRLSource, signatureOCSPSource, validationCertificatePool);
		final RevocationToken revocationToken = offlineVerifier.check(certToken);
		if (revocationToken != null && logEnabled) {
			LOG.trace(" > Revocation data: {} found offline for: {}", revocationToken.getAbbreviation(), certToken.getAbbreviation());
		}
		return revocationToken;
	}

	private boolean shouldCheckOnLine(final CertificateToken certificateToken) {

		final boolean expired = certificateToken.isExpiredOn(currentTime);
		if (!expired) {

			return true;
		}
		final CertificateToken issuerCertToken = certificateToken.getIssuerToken();
		// issuerCertToken cannot be null
		final boolean expiredCertOnCRLExtension = issuerCertToken.hasExpiredCertOnCRLExtension();
		if (expiredCertOnCRLExtension) {

			certificateToken.extraInfo().infoExpiredCertOnCRL();
			return true;
		}
		final Date expiredCertsRevocationFromDate = getExpiredCertsRevocationFromDate(certificateToken);
		if (expiredCertsRevocationFromDate != null) {

			certificateToken.extraInfo().infoExpiredCertsRevocationFromDate(expiredCertsRevocationFromDate);
			return true;
		}
		return false;
	}

	private Date getExpiredCertsRevocationFromDate(final CertificateToken certificateToken) {

		final CertificateToken trustAnchor = certificateToken.getTrustAnchor();
		if (trustAnchor != null) {

			final List<ServiceInfo> serviceInfoList = trustAnchor.getAssociatedTSPS();
			if (serviceInfoList != null) {

				final Date notAfter = certificateToken.getNotAfter();
				for (final ServiceInfo serviceInfo : serviceInfoList) {

					final Date date = serviceInfo.getExpiredCertsRevocationInfo();
					if (date != null && date.before(notAfter)) {

						if (serviceInfo.getStatusEndDate() == null) {

							// Service is still active (operational)
							return date;
						}
					}
				}
			}
		}
		return null;
	}

	@Override
	public Set<CertificateToken> getProcessedCertificates() {

		return Collections.unmodifiableSet(processedCertificates.keySet());
	}

	@Override
	public Set<RevocationToken> getProcessedRevocations() {

		return Collections.unmodifiableSet(processedRevocations.keySet());
	}

	@Override
	public Set<TimestampToken> getProcessedTimestamps() {

		return Collections.unmodifiableSet(processedTimestamps.keySet());
	}

	/**
	 * This method returns the human readable representation of the ValidationContext.
	 *
	 * @param indentStr
	 * @return
	 */

	public String toString(String indentStr) {

		try {

			final StringBuilder builder = new StringBuilder();
			builder.append(indentStr).append("ValidationContext[").append('\n');
			indentStr += "\t";
			// builder.append(indentStr).append("Validation time:").append(validationDate).append('\n');
			builder.append(indentStr).append("Certificates[").append('\n');
			indentStr += "\t";
			for (CertificateToken certToken : processedCertificates.keySet()) {

				builder.append(certToken.toString(indentStr));
			}
			indentStr = indentStr.substring(1);
			builder.append(indentStr).append("],\n");
			indentStr = indentStr.substring(1);
			builder.append(indentStr).append("],\n");
			return builder.toString();
		} catch (Exception e) {

			return super.toString();
		}
	}

	@Override
	public String toString() {

		return toString("");
	}

	class TokensToProcess {

		private final Map<Token, Boolean> tokensToProcess = new HashMap<Token, Boolean>();

		/**
		 * This method returns a token to verify. If there is no more tokens to verify null is returned.
		 *
		 * @return token to verify or null
		 */
		synchronized Token get() {

			for (final Entry<Token, Boolean> entry : tokensToProcess.entrySet()) {
				if (entry.getValue() == null) {

					entry.setValue(true);
					final Token token = entry.getKey();
					if (logEnabled) {
						LOG.trace("- Get {} to check: {} / {}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation(), tokensToProcess.size()});
					}
					return token;
				}
			}
			return null;
		}

		/**
		 * Adds a new token to the list of tokens to verify only if it was not already verified.
		 *
		 * @param token token to verify
		 * @return true if the token was not yet verified, false otherwise.
		 */
		synchronized boolean put(final Token token) {

			if (token == null) {
				return false;
			}
			if (tokensToProcess.containsKey(token)) {

				if (logEnabled) {
					LOG.trace("Token was already in the list {}:{}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation()});
				}
				return false;
			}
			tokensToProcess.put(token, null);
			if (logEnabled) {
				LOG.trace("+ New {} to check: {} / {}", new Object[]{token.getClass().getSimpleName(), token.getAbbreviation(), tokensToProcess.size()});
			}
			return true;
		}
	}
}
