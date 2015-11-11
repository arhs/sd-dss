package eu.europa.ec.markt.dss.validation102853.tsl;

import java.io.File;

import org.junit.Assert;
import org.junit.Test;

import eu.europa.ec.markt.dss.validation102853.KeyStoreCertificateSource;
import eu.europa.ec.markt.dss.validation102853.https.CommonsDataLoader;

public class TrustedListCertificateSourceTest {
	
	@Test
	public void test1() throws Exception {
		
		TrustedListsCertificateSource source = new TrustedListsCertificateSource();
		source.setDataLoader(new CommonsDataLoader());
		KeyStoreCertificateSource keyStoreCertificateSource = new KeyStoreCertificateSource(
				new File("src/test/resources/tsl-keystore.jks"), "dss-password");
		source.setKeyStoreCertificateSource(keyStoreCertificateSource);
		source.setLotlUrl("https://ec.europa.eu/information_society/policy/esignature/trusted-list/tl-mp.xml");
		source.setTslRefreshPolicy(TSLRefreshPolicy.NEVER);
		source.setCheckSignature(false);
		source.init();
		
		Assert.assertTrue(source.getCertificates().size() > 0);

	}
	
}
