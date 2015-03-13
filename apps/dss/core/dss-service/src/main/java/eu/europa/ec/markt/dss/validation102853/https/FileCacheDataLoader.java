/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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
package eu.europa.ec.markt.dss.validation102853.https;

import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.DigestAlgorithm;
import eu.europa.ec.markt.dss.ResourceLoader;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.loader.Protocol;

/**
 * This class provides some caching features to handle the resources. The default cache folder is set to {@code java.io.tmpdir}. The urls of the resources is transformed to the
 * file name by replacing the special characters by {@code _}
 */
public class FileCacheDataLoader extends CommonDataLoader {

	private static final Logger LOG = LoggerFactory.getLogger(FileCacheDataLoader.class);

	protected File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir"));

	protected ResourceLoader resourceLoader = new ResourceLoader();

	protected List<String> toBeLoaded;

	protected List<String> toIgnored;

	/**
	 * This method allows to set the file cache directory. If the cache folder does not exists then it's created.
	 *
	 * @param fileCacheDirectory {@code File} pointing the cache folder to be used.
	 */
	public void setFileCacheDirectory(final File fileCacheDirectory) {

		this.fileCacheDirectory = fileCacheDirectory;
		this.fileCacheDirectory.mkdirs();
	}

	public void setResourceLoader(final ResourceLoader resourceLoader) {
		this.resourceLoader = resourceLoader;
	}

	/**
	 * This methods allows to indicate if the resource must be obtained. If this method has been invoked then only the provided URL will be processed.
	 *
	 * @param url to be processed
	 */
	public void addToBeLoaded(final String url) {

		if (toBeLoaded == null) {

			toBeLoaded = new ArrayList<String>();
		}
		if (DSSUtils.isNotBlank(url)) {

			toBeLoaded.add(url);
		}
	}

	/**
	 * This methods allows to indicate which resources must be ignored. It is useful in a test environment where some of fake sources a not available. It prevents to wait for the
	 * timeout.
	 *
	 * @param urlString to be ignored. It can be the original URL or the cache file name
	 */
	public void addToBeIgnored(final String urlString) {

		if (toIgnored == null) {

			toIgnored = new ArrayList<String>();
		}
		if (DSSUtils.isNotBlank(urlString)) {

			final String normalizedFileName = ResourceLoader.getNormalizedFileName(urlString);
			toIgnored.add(normalizedFileName);
		}
	}

	@Override
	public byte[] get(final String url, final boolean refresh) throws DSSException {

		if (toBeLoaded != null && !toBeLoaded.contains(url)) {
			return null;
		}
		final String cacheFileName = ResourceLoader.getNormalizedFileName(url);
		final byte[] cachedFileContent = getCachedFileContent(cacheFileName, refresh);
		if (cachedFileContent != null) {
			return cachedFileContent;
		}
		final byte[] returnedBytes;
		if (!isNetworkProtocol(url)) {
			returnedBytes = getContentUsingNotNetworkProtocol(url);
		} else {
			returnedBytes = super.get(url);
		}
		if (returnedBytes != null && returnedBytes.length != 0) {

			final File out = getCacheFile(cacheFileName);
			DSSUtils.saveToFile(returnedBytes, out);
		}
		return returnedBytes;
	}

	private byte[] getContentUsingNotNetworkProtocol(final String url) {

		final String resourcePath = resourceLoader.getAbsoluteResourceFolder(url.trim());
		final File fileResource = new File(resourcePath);
		final byte[] bytes = DSSUtils.toByteArray(fileResource);
		return bytes;
	}

	private byte[] getCachedFileContent(final String cacheFileName, final boolean refresh) {

		final File file = getCacheFile(cacheFileName);
		final boolean fileExists = file.exists();
		if (fileExists && !refresh) {

			LOG.debug("Cached file was used");
			final byte[] bytes = DSSUtils.toByteArray(file);
			return bytes;
		} else {
			if (!fileExists) {
				LOG.debug("There is no cached file!");
			} else {
				LOG.debug("The refresh is forced!");
			}
		}
		return null;
	}

	@Override
	public byte[] get(final String url) throws DSSException {

		return get(url, false);
	}

	protected boolean isNetworkProtocol(final String urlString) {

		final String normalizedUrl = urlString.trim().toLowerCase();
		return Protocol.isHttpUrl(normalizedUrl) || Protocol.isLdapUrl(normalizedUrl) || Protocol.isFtpUrl(normalizedUrl);
	}

	private File getCacheFile(final String fileName) {

		final String trimmedFileName = fileName.trim();
		if (toIgnored != null && toIgnored.contains(trimmedFileName)) {

			throw new DSSException("Part of urls to ignore.");
		}
		LOG.debug("Cached file: " + fileCacheDirectory + "/" + trimmedFileName);
		final File file = new File(fileCacheDirectory, trimmedFileName);
		return file;
	}

	/**
	 * Allows to load the file for a given file name from the cache folder.
	 *
	 * @return the content of the file or {@code null} if the file does not exist
	 */
	public byte[] loadFileFromCache(final String urlString) {

		final String fileName = ResourceLoader.getNormalizedFileName(urlString);
		final File file = getCacheFile(fileName);
		if (file.exists()) {

			final byte[] bytes = DSSUtils.toByteArray(file);
			return bytes;
		}
		return null;
	}

	/**
	 * Allows to add a given array of {@code byte} as a cache file representing by the {@code urlString}.
	 *
	 * @param urlString the URL to add to the cache
	 * @param bytes     the content of the cache file
	 */
	public void saveBytesInCache(final String urlString, final byte[] bytes) {

		final String fileName = ResourceLoader.getNormalizedFileName(urlString);
		final File out = getCacheFile(fileName);
		DSSUtils.saveToFile(bytes, out);
	}

	// TODO-Bob (22/02/2015):  request id should be added (or something like this) to cope with nonce extension of the OCSP for example...
	@Override
	public byte[] post(final String urlString, final byte[] requestBytes, boolean refresh) throws DSSException {

		final String fileName = ResourceLoader.getNormalizedFileName(urlString);

		final byte[] digest = DSSUtils.digest(DigestAlgorithm.MD5, requestBytes);
		final String digestHexEncoded = DSSUtils.toHex(digest);
		final String cacheFileName = fileName + "." + digestHexEncoded;
		final byte[] cachedFileContent = getCachedFileContent(cacheFileName, refresh);
		if (cachedFileContent != null) {
			return cachedFileContent;
		}
		if (!isNetworkProtocol(urlString)) {
			return getContentUsingNotNetworkProtocol(urlString);
		}

		final byte[] returnedBytes = super.post(urlString, requestBytes);
		if (returnedBytes.length != 0) {

			final File cacheFile = getCacheFile(cacheFileName);
			DSSUtils.saveToFile(returnedBytes, cacheFile);
		}
		return returnedBytes;
	}

	@Override
	public byte[] post(final String urlString, final byte[] requestBytes) throws DSSException {

		return post(urlString, requestBytes, false);
	}

	public List<String> getToBeLoaded() {
		return toBeLoaded == null ? null : Collections.unmodifiableList(toBeLoaded);
	}

	public List<String> getToIgnored() {
		return toIgnored == null ? null : Collections.unmodifiableList(toIgnored);
	}
}
