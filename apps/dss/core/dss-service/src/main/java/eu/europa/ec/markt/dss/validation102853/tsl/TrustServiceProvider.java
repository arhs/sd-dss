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

package eu.europa.ec.markt.dss.validation102853.tsl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import eu.europa.ec.markt.tsl.jaxb.tsl.InternationalNamesType;
import eu.europa.ec.markt.tsl.jaxb.tsl.MultiLangNormStringType;
import eu.europa.ec.markt.tsl.jaxb.tsl.PostalAddressType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryInstanceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.ServiceHistoryType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPServiceType;
import eu.europa.ec.markt.tsl.jaxb.tsl.TSPType;

/**
 * Wrapper for the tag TrustServiceProvider
 *
 * @version $Revision: 1049 $ - $Date: 2011-06-27 17:25:05 +0200 (Mon, 27 Jun 2011) $
 */

public class TrustServiceProvider {

	private TSPType tspType;

	/**
	 * The default constructor for TrustServiceProvider.
	 *
	 * @param tspType
	 */
	public TrustServiceProvider(TSPType tspType) {

		this.tspType = tspType;
	}

	/**
	 * Retrieves the list of current and historical services from the encapsulated provider
	 *
	 * @return The list of current and history services, in descending order.
	 */
	public List<AbstractTrustService> getTrustServiceList() {

		final List<AbstractTrustService> providerList = new ArrayList<AbstractTrustService>();
		for (final TSPServiceType service : tspType.getTSPServices().getTSPService()) {

			final List<AbstractTrustService> trustServiceList = new ArrayList<AbstractTrustService>();
			// System.out.println();
			// final TSPServiceInformationType serviceInformation = service.getServiceInformation();
			// System.out.println("#------> " + serviceInformation.getServiceName());
			// System.out.println("#------> " + serviceInformation.getServiceTypeIdentifier());
			// System.out.println("#------> " + serviceInformation.getServiceStatus());

			final CurrentTrustService currentService = new CurrentTrustService(service);
			trustServiceList.add(currentService);

			final ServiceHistoryType serviceHistory = service.getServiceHistory();
			if (serviceHistory != null) {

				for (final ServiceHistoryInstanceType serviceHistoryItem : serviceHistory.getServiceHistoryInstance()) {

					final HistoricalTrustService historicalService = new HistoricalTrustService(serviceHistoryItem);
					trustServiceList.add(historicalService);
				}
			}

			// The Services must be sorted in descending order CROBIES 2.2.15
			// TODO: (Bob: 2014 Feb 21) The TSL is already sorted. To be removed
			Collections.sort(trustServiceList, new Comparator<AbstractTrustService>() {

				@Override
				public int compare(AbstractTrustService o1, AbstractTrustService o2) {

					return -o1.getStatusStartDate().compareTo(o2.getStatusStartDate());
				}
			});

			AbstractTrustService previous = currentService;
			for (AbstractTrustService trustService : trustServiceList) {

				if (trustService instanceof HistoricalTrustService) {

					((HistoricalTrustService) trustService).setPreviousEntry(previous);
				}
				previous = trustService;
			}
			providerList.addAll(trustServiceList);
		}
		return providerList;
	}

	private String getEnglishOrFirst(InternationalNamesType names) {

		if (names == null) {
			return null;
		}
		for (MultiLangNormStringType s : names.getName()) {
			if ("en".equalsIgnoreCase(s.getLang())) {
				return s.getValue();
			}
		}
		return names.getName().get(0).getValue();
	}

	public String getName() {

		return getEnglishOrFirst(tspType.getTSPInformation().getTSPName());
	}

	public String getTradeName() {

		return getEnglishOrFirst(tspType.getTSPInformation().getTSPTradeName());
	}

	public String getPostalAddress() {

		PostalAddressType a = null;
		if (tspType.getTSPInformation().getTSPAddress() == null) {
			return null;
		}
		for (PostalAddressType c : tspType.getTSPInformation().getTSPAddress().getPostalAddresses().getPostalAddress()) {
			if ("en".equalsIgnoreCase(c.getLang())) {
				a = c;
				break;
			}
		}
		if (a == null) {
			a = tspType.getTSPInformation().getTSPAddress().getPostalAddresses().getPostalAddress().get(0);
		}
		return a.getStreetAddress() + ", " + a.getPostalCode() + " " + a.getLocality() + ", " + a.getStateOrProvince() + a.getCountryName();
	}

	public String getElectronicAddress() {

		if (tspType.getTSPInformation().getTSPAddress().getElectronicAddress() == null) {
			return null;
		}
		return tspType.getTSPInformation().getTSPAddress().getElectronicAddress().getURI().get(0).getValue();
	}
}