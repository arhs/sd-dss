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
package eu.europa.ec.markt.dss.dao;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * This class uses a property file to read the proxy preferences.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ProxyFileDao implements ProxyDao {

	private static final Logger LOG = LoggerFactory.getLogger(ProxyFileDao.class);

	protected Map<ProxyKey, ProxyPreference> proxyPreferences = new HashMap<ProxyKey, ProxyPreference>();

	public ProxyFileDao(final String proxyPreferencesResourcePath) {

		LOG.info(">>> ProxyFileDao: " + proxyPreferencesResourcePath);
		try {

			final InputStream propertyInputStream = DSSUtils.getResource(proxyPreferencesResourcePath);
			final Properties properties = new Properties();
			properties.load(propertyInputStream);
			for (final Map.Entry keySet : properties.entrySet()) {

				final String key = (String) keySet.getKey();
				final String value = (String) keySet.getValue();
				LOG.trace(key + "=" + (key.contains("password") ? "******" : value));
				final ProxyKey proxyKey = ProxyKey.fromKey(key);
				if (proxyKey == null) {
					continue;
				}
				final ProxyPreference proxyPreference = new ProxyPreference(proxyKey, value);
				proxyPreferences.put(proxyKey, proxyPreference);
			}
		} catch (IOException e) {
			throw new DSSException("Error when initialising ProxyFileDao", e);
		}
	}

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
		return "ProxyFileDao{" +
			  "proxyPreferences=" + proxyPreferences +
			  '}';
	}
}
