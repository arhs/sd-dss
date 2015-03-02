package eu.europa.ec.markt.dss.dao;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in memory implementation of {@code ProxyDao}
 * <p/>
 *
 * @author Robert Bielecki
 */
public class ProxyInMemoryDao implements ProxyDao {

	private static final Logger LOG = LoggerFactory.getLogger(ProxyInMemoryDao.class);

	protected Map<ProxyKey, ProxyPreference> proxyPreferences = new HashMap<ProxyKey, ProxyPreference>();

	@Override
	public ProxyPreference get(final ProxyKey proxyKey) {

		final ProxyPreference proxyPreference = proxyPreferences.get(proxyKey);
		return proxyPreference;
	}

	@Override
	public Collection<ProxyPreference> getAll() {

		return Collections.unmodifiableCollection(proxyPreferences.values());
	}

	@Override
	public void update(final ProxyPreference proxyPreference) {

		proxyPreferences.put(proxyPreference.getProxyKey(), proxyPreference);
	}

	@Override
	public String toString() {
		return "ProxyInMemoryDao{" +
			  "proxyPreferences=" + proxyPreferences +
			  '}';
	}
}
