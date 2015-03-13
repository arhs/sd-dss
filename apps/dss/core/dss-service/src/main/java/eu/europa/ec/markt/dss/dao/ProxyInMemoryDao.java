/*
 * SD-DSS - Digital Signature Services
 *
 * Copyright (C) 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * Developed by: 2015 ARHS SpikeSeed S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-spikeseed.com
 *
 * This file is part of the "https://github.com/arhs/sd-dss" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "SD-DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

package eu.europa.ec.markt.dss.dao;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * An in memory implementation of {@code ProxyDao}
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
