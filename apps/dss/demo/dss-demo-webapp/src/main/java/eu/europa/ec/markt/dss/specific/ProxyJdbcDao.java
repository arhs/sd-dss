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
package eu.europa.ec.markt.dss.specific;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.sql.DataSource;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.dao.ProxyDao;
import eu.europa.ec.markt.dss.dao.ProxyKey;
import eu.europa.ec.markt.dss.dao.ProxyPreference;

/**
 * JDBC Implementation for a ProxyDao.
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ProxyJdbcDao implements ProxyDao {

    private static final Logger LOG = LoggerFactory.getLogger(ProxyJdbcDao.class);

    private DataSource dataSource;

    public ProxyJdbcDao() {

        LOG.info(">>> ProxyJdbcDao");
    }

    @Override
    public ProxyPreference get(final ProxyKey proxyKey) {

        final String sql = "select * from PROXY_PREFERENCES where PROXY_KEY = :key";

        Connection connection = null;
        PreparedStatement preparedStatement = null;
        ResultSet resultSet = null;
        try {

            connection = getDataSource().getConnection();
            preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setString(1, proxyKey.getKeyName());
            resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {

                final ProxyPreference proxyPreference = new ProxyPreference();
                final String proxyKeyString = resultSet.getString("PROXY_KEY");
                proxyPreference.setProxyKey(proxyKeyString);
                proxyPreference.setValue(resultSet.getString("PROXY_VALUE"));
                return proxyPreference;
            }
            return null;
        } catch (SQLException e) {
            throw new ProxyDaoException(e);
        } finally {
            try {
                if (resultSet != null) {
                    resultSet.close();
                }
                if (preparedStatement != null) {
                    preparedStatement.close();
                }

                if (connection != null && !connection.isClosed()) {
                    connection.close();
                }
            } catch (SQLException e) {

            }
        }
    }

    @Override
    public Collection<ProxyPreference> getAll() {

        String sql = "select * from PROXY_PREFERENCES";
        Connection connection = null;
        PreparedStatement ps = null;
        ResultSet rs = null;
        List<ProxyPreference> proxyPreferences = new ArrayList<ProxyPreference>();
        try {
            connection = getDataSource().getConnection();
            ps = connection.prepareStatement(sql);
            rs = ps.executeQuery();
            while (rs.next()) {
                ProxyPreference pp = new ProxyPreference();
                pp.setProxyKey(rs.getString("PROXY_KEY"));
                pp.setValue(rs.getString("PROXY_VALUE"));
                proxyPreferences.add(pp);
            }
        } catch (SQLException e) {
            throw new ProxyDaoException(e);
        } finally {
            try {
                if (rs != null) {
                    rs.close();
                }
                if (ps != null) {
                    ps.close();
                }

                if (connection != null && !connection.isClosed()) {
                    connection.close();
                }
            } catch (SQLException e) {

            }
        }
        return proxyPreferences;
    }

    /**
     * @param dataSource
     */
    public void setDataSource(final DataSource dataSource) {
        this.dataSource = dataSource;
    }

    private DataSource getDataSource() {

        if (dataSource == null) {
            throw new IllegalStateException("You must set the datasource to use this class!");
        }
        return dataSource;
    }

    @Override
    public void update(final ProxyPreference proxyPreference) {

        final String sql = "update PROXY_PREFERENCES set PROXY_VALUE = :value where PROXY_KEY = :key";
        Connection connection = null;
        PreparedStatement preparedStatement = null;
        try {
            connection = getDataSource().getConnection();
            preparedStatement = connection.prepareStatement(sql);
            preparedStatement.setString(1, proxyPreference.getValue());
            preparedStatement.setString(2, proxyPreference.getProxyKey().getKeyName());
            preparedStatement.executeUpdate();
        } catch (SQLException e) {
            throw new ProxyDaoException(e);
        } finally {
            try {
                if (preparedStatement != null) {
                    preparedStatement.close();
                }

                if (connection != null && !connection.isClosed()) {
                    connection.close();
                }
            } catch (SQLException e) {
            }
        }
    }
}
