package eu.europa.ec.markt.dss.validation102853.ocsp;

import org.bouncycastle.asn1.DEROctetString;

import eu.europa.ec.markt.dss.DSSUtils;

/**
 * TODO
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author Robert Bielecki
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
class NonceContainer {

	/**
	 * This variable is used to prevent the replay attack.
	 */
	DEROctetString nonce;

	public NonceContainer() {

		final long currentTimeNonce = System.currentTimeMillis();
		nonce = new DEROctetString(DSSUtils.toByteArray(currentTimeNonce));
	}
}
