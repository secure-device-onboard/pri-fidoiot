// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fidoalliance.fdo.storage;

import java.io.IOException;
import java.io.InputStream;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Timestamp;
import java.sql.Types;
import java.util.Calendar;
import java.util.NoSuchElementException;
import java.util.UUID;
import javax.sql.DataSource;
import org.fidoalliance.fdo.protocol.Composite;
import org.fidoalliance.fdo.protocol.Const;
import org.fidoalliance.fdo.protocol.RendezvousInfoDecoder;
import org.fidoalliance.fdo.serviceinfo.DevMod;

/**
 * Owner Database Manager.
 */
public class OwnerDbManager {

  /**
   * Creates owner tables.
   *
   * @param dataSource A SQL datasource.
   */
  public void createTables(DataSource dataSource) {
    try (Connection conn = dataSource.getConnection();
        Statement stmt = conn.createStatement()) {

      String sql =
          "CREATE TABLE IF NOT EXISTS "
              + "OWNER_CUSTOMERS ("
              + "CUSTOMER_ID INT NOT NULL DEFAULT 1, "
              + "NAME VARCHAR(255), "
              + "KEYS VARCHAR(4096), "
              + "UNIQUE (CUSTOMER_ID)"
              + ");";

      stmt.executeUpdate(sql);

      sql =
          "CREATE TABLE IF NOT EXISTS "
              + "TO2_DEVICES("
              + "GUID CHAR(36) PRIMARY KEY, "
              + "VOUCHER BLOB, "
              + "WAIT_SECONDS_REQUEST INT NOT NULL DEFAULT 3600, "
              + "WAIT_SECONDS_RESPONSE INT NULL DEFAULT NULL, "
              + "CREATED TIMESTAMP NOT NULL, "
              + "TO0_STARTED TIMESTAMP NULL DEFAULT NULL, "
              + "TO0_COMPLETED TIMESTAMP NULL DEFAULT NULL, "
              + "TO2_STARTED TIMESTAMP NULL DEFAULT NULL, "
              + "TO2_COMPLETED TIMESTAMP NULL DEFAULT NULL, "
              + "REPLACEMENT_GUID CHAR(36), "
              + "REPLACEMENT_RVINFO BLOB, "
              + "REPLACEMENT_HMAC BLOB, "
              + "CUSTOMER_ID INT , "
              + "REPLACEMENT_VOUCHER BLOB, "
              + "OWNER_SERVICE_INFO_MTU_SIZE INT NULL DEFAULT NULL, "
              + "PRIMARY KEY (GUID), "
              + "UNIQUE (GUID), "
              + "FOREIGN KEY (CUSTOMER_ID) REFERENCES "
              + "OWNER_CUSTOMERS(CUSTOMER_ID) ON DELETE CASCADE"
              + ");";

      stmt.executeUpdate(sql);

      sql =
          "CREATE TABLE IF NOT EXISTS "
              + "TO2_SESSIONS("
              + "SESSION_ID CHAR(36) PRIMARY KEY, "
              + "VOUCHER BLOB, "
              + "OWNER_STATE BLOB,"
              + "CIPHER_NAME VARCHAR(36), "
              + "NONCETO2PROVEDV BINARY(16), "
              + "NONCETO2SETUPDV BINARY(16), "
              + "SIGINFOA BLOB, "
              + "SERVICEINFO_BLOB BLOB, "
              + "CREATED TIMESTAMP,"
              + "UPDATED TIMESTAMP,"
              + "PRIMARY KEY (SESSION_ID), "
              + "UNIQUE (SESSION_ID)"
              + ");";

      stmt.executeUpdate(sql);

      sql =
          "CREATE TABLE IF NOT EXISTS "
              + "TO2_SETTINGS("
              + "ID INT NOT NULL, "
              + "DEVICE_SERVICE_INFO_MTU_SIZE INT NOT NULL, "
              + "OWNER_MTU_THRESHOLD INT NOT NULL, "
              + "PRIMARY KEY (ID), "
              + "UNIQUE (ID)"
              + ");";

      stmt.executeUpdate(sql);

      sql = "CREATE TABLE IF NOT EXISTS "
          + "DEVICE_MODULE_INFO ("
          + "GUID CHAR(36) NOT NULL,"
          + "ACTIVE BOOLEAN NOT NULL, "
          + "OS_NAME VARCHAR(255) NOT NULL, "
          + "OS_VERSION VARCHAR(255) NOT NULL,"
          + "OS_ARCH VARCHAR(255) NOT NULL , "
          + "DEVICE_TYPE VARCHAR(255) NOT NULL, "
          + "SERIAL_NUMBER VARCHAR(255) NULL DEFAULT NULL, "
          + "PATH_SEPARATOR VARCHAR(2) NOT NULL, "
          + "FILE_NAME_SEPARATOR VARCHAR(2) NULL DEFAULT NULL,"
          + "NEW_LINE_SEQUENCE VARCHAR(4) NULL DEFAULT NULL,"
          + "TMP_DIR VARCHAR(512) NULL DEFAULT NULL,"
          + "BIN_DIR VARCHAR(512) NULL DEFAULT NULL,"
          + "PROG_ENV VARCHAR(512) NULL DEFAULT NULL,"
          + "BIN_FORMATS VARCHAR(512) NOT NULL,"
          + "MUD_URL VARCHAR(512) NULL DEFAULT NULL,"
          + "MODULES CLOB NOT NULL,"
          + "CREATED TIMESTAMP, "
          + "FOREIGN KEY (GUID) REFERENCES "
          + "TO2_DEVICES(GUID) ON DELETE CASCADE"
          + ");";

      stmt.executeUpdate(sql);

      sql = "CREATE TABLE IF NOT EXISTS "
          + "SYSTEM_MODULE_RESOURCE("
          + "RESOURCE_ID IDENTITY NOT NULL, "
          + "CONTENT BLOB NULL DEFAULT NULL,"
          + "CONTENT_TYPE_TAG CHAR(255) NOT NULL, "
          + "CONTENT_RESOURCE_TAG BIGINT NULL DEFAULT NULL, "
          + "PRIORITY INT NOT NULL DEFAULT 1, "
          + "FILE_NAME_TAG VARCHAR(1280) NULL DEFAULT NULL, "
          + "GUID_TAG CHAR(36) NULL DEFAULT NULL, "
          + "DEVICE_TYPE_TAG VARCHAR(255) NULL DEFAULT NULL, "
          + "OS_NAME_TAG VARCHAR(255) NULL DEFAULT NULL, "
          + "OS_VERSION_TAG VARCHAR(255) NULL DEFAULT NULL, "
          + "ARCHITECTURE_TAG VARCHAR(255) NULL DEFAULT NULL, "
          + "HASH_TAG VARCHAR(255) NULL DEFAULT NULL, "
          + "UPDATED TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP(), "
          + "PRIMARY KEY (RESOURCE_ID), "
          + "UNIQUE (RESOURCE_ID)"
          + ");";

      stmt.executeUpdate(sql);

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Imports ownership voucher.
   *
   * @param ds      A SQL datasource.
   * @param voucher The ownership voucher to import.
   */
  public void importVoucher(DataSource ds, Composite voucher) {

    Composite ovh = voucher.getAsComposite(Const.OV_HEADER);
    UUID guid = ovh.getAsUuid(Const.OVH_GUID);

    String sql = ""
        + "MERGE INTO TO2_DEVICES  "
        + "KEY (GUID) "
        + "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?); ";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      pstmt.setString(1, guid.toString());
      pstmt.setBytes(2, voucher.toBytes());
      pstmt.setInt(3, 3600);
      pstmt.setInt(4, 0);
      Timestamp created = new Timestamp(Calendar.getInstance().getTimeInMillis());
      pstmt.setTimestamp(5, created);
      pstmt.setTimestamp(6, null);
      pstmt.setTimestamp(7, null);
      pstmt.setTimestamp(8, null);
      pstmt.setTimestamp(9, null);
      pstmt.setString(10, guid.toString());
      pstmt.setBytes(11, ovh
          .getAsComposite(Const.OVH_RENDEZVOUS_INFO).toBytes());
      pstmt.setBytes(12, null);
      pstmt.setInt(13, 1);
      pstmt.setBytes(14, null);
      pstmt.setInt(15, 0);

      pstmt.executeUpdate();

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Removes a Voucher.
   *
   * @param ds   A Datasource.
   * @param guid The device guid.
   * @return The number of database objects affected.
   */
  public int removeVoucher(DataSource ds, UUID guid) {

    int result = 0;

    String sql = ""
        + "DELETE FROM TO2_DEVICES WHERE GUID = ?";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      pstmt.setString(1, guid.toString());

      result = pstmt.executeUpdate();

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }

    return result;
  }


  /**
   * Update the replacementRvInfo for given currentGuid.
   *
   * @param ds                Datasource instance
   * @param currentGuid       The GUID of the device for which updates need to be made.
   * @param replacementRvInfo The replacement/new RvInfo for the device.
   */
  public void updateDeviceReplacementRvinfo(DataSource ds, UUID currentGuid,
      String replacementRvInfo) {

    String sql = "UPDATE TO2_DEVICES"
        + " SET REPLACEMENT_RVINFO = ?"
        + " WHERE GUID = ?;";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setBytes(1, Composite.fromObject(replacementRvInfo).toBytes());
      pstmt.setString(2, currentGuid.toString());
      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Update the replacementRvInfo for given currentGuid.
   *
   * @param ds             Datasource instance
   * @param currentGuid    The GUID of the device for which updates need to be made.
   * @param replacementKey Customer ID for replacement key.
   */
  public void updateReplacementKeyCustomerId(DataSource ds, UUID currentGuid,
      int replacementKey) {

    String sql = "UPDATE TO2_DEVICES"
        + " SET CUSTOMER_ID = ?"
        + " WHERE GUID = ?;";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setInt(1, replacementKey);
      pstmt.setString(2, currentGuid.toString());
      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Update the replacementGuid for given currentGuid.
   *
   * @param ds              Datasource instance
   * @param currentGuid     The GUID of the device for which updates need to be made.
   * @param replacementGuid The replacement/new GUID for the device.
   */
  public void updateDeviceReplacementGuid(DataSource ds, UUID currentGuid, UUID replacementGuid) {

    String sql = "UPDATE TO2_DEVICES"
        + " SET REPLACEMENT_GUID = ?"
        + " WHERE GUID = ?;";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, replacementGuid.toString());
      pstmt.setString(2, currentGuid.toString());
      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Load default value of maximum serviceinfo that owner can receive.
   *
   * @param ds Datasource instance
   */
  public void loadTo2Settings(DataSource ds) {

    String sql = "MERGE INTO TO2_SETTINGS ("
        + "ID,"
        + "DEVICE_SERVICE_INFO_MTU_SIZE, "
        + "OWNER_MTU_THRESHOLD ) "
        + "VALUES (?,?,?);";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setInt(1, 1);
      pstmt.setInt(2, Const.SERVICE_INFO_MTU_MIN_SIZE);
      pstmt.setInt(3, Const.OWNER_THRESHOLD_DEFAULT_MTU_SIZE);
      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Update the given field with the required MTU size in TO2_SETTINGS table.
   *
   * @param ds    Datasource instance
   * @param field Database column name
   * @param mtu   maximum MTU size
   */
  public void updateMtu(DataSource ds, String field, int mtu) {

    String sql = "UPDATE TO2_SETTINGS" + " SET " + field + " = ?" + " WHERE ID = 1;";

    if (field.equals("DEVICE_SERVICE_INFO_MTU_SIZE")) {
      if (mtu < 0) {
        System.out.println("Received value must be > 0. "
            + "Updating MTU size to default minimum of "
            + Const.SERVICE_INFO_MTU_MIN_SIZE);
        mtu = Const.SERVICE_INFO_MTU_MIN_SIZE;
      } else if (mtu < Const.SERVICE_INFO_MTU_MIN_SIZE) {
        System.out.println("Received value less than default minimum. "
            + "Updating MTU size to default minimum of "
            + Const.SERVICE_INFO_MTU_MIN_SIZE);
        mtu = Const.SERVICE_INFO_MTU_MIN_SIZE;
      } else if (mtu > Const.OWNER_THRESHOLD_DEFAULT_MTU_SIZE) {
        System.out.println("MTU size greater than maximum allowed. "
            +  "Updating MTU size to maximum limit of "
            +  Const.OWNER_THRESHOLD_DEFAULT_MTU_SIZE);
        mtu = Const.OWNER_THRESHOLD_DEFAULT_MTU_SIZE;
      }
    }

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, String.valueOf(mtu));
      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Ads a customer to the Customers table.
   *
   * @param ds   The datasource to use.
   * @param id   The id of the customer.
   * @param name The name of the customer.
   * @param keys A PEM string containing public keys.
   */
  public void addCustomer(DataSource ds, int id, String name, String keys) {

    String sql = ""
        + "MERGE INTO OWNER_CUSTOMERS   "
        + "KEY (CUSTOMER_ID) "
        + "VALUES (?,?,?); ";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setInt(1, id);
      pstmt.setString(2, name);
      pstmt.setString(3, keys);
      pstmt.executeUpdate();

    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Sets the device property of a field in the device info table.
   *
   * @param pstmt    The SQL prepare statement.
   * @param columnId The column id to set.
   * @param mapKey   The DevMod key we are setting.
   * @param map      The map containing the values of the DevMod keys.
   * @throws SQLException An SQL Exception.
   */
  private void setDeviceInfoProperty(PreparedStatement pstmt,
      int columnId,
      String mapKey,
      Composite map) throws SQLException {
    if (map.containsKey(mapKey)) {
      Object value = map.get(mapKey);
      if (value instanceof String) {
        pstmt.setString(columnId, value.toString());
      } else if (value instanceof Boolean) {
        pstmt.setBoolean(columnId, (Boolean) value);
      }
    } else {
      pstmt.setNull(columnId, Types.CHAR);
    }
  }

  /**
   * Add device type to owner serviceinfo mapping.
   *
   * @param ds  Datasource instance.
   * @param map A map containing all DevMod Keys and values.
   */
  public void addDeviceInfo(DataSource ds, Composite map) {

    String sql = "INSERT INTO DEVICE_MODULE_INFO ("
        + "GUID,"
        + "ACTIVE,"
        + "OS_NAME, "
        + "OS_VERSION, "
        + "OS_ARCH, "
        + "DEVICE_TYPE, "
        + "SERIAL_NUMBER, "
        + "PATH_SEPARATOR, "
        + "FILE_NAME_SEPARATOR, "
        + "NEW_LINE_SEQUENCE,"
        + "TMP_DIR,"
        + "BIN_DIR,"
        + "PROG_ENV,"
        + "BIN_FORMATS,"
        + "MUD_URL, "
        + "MODULES, "
        + "CREATED"
        + ") VALUES ("
        + "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?"
        + ");";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      setDeviceInfoProperty(pstmt, 1, "guid", map);
      setDeviceInfoProperty(pstmt, 2, DevMod.KEY_ACTIVE, map);
      setDeviceInfoProperty(pstmt, 3, DevMod.KEY_OS, map);
      setDeviceInfoProperty(pstmt, 4, DevMod.KEY_VERSION, map);
      setDeviceInfoProperty(pstmt, 5, DevMod.KEY_ARCH, map);
      setDeviceInfoProperty(pstmt, 6, DevMod.KEY_DEVICE, map);
      setDeviceInfoProperty(pstmt, 7, DevMod.KEY_SN, map);
      setDeviceInfoProperty(pstmt, 8, DevMod.KEY_PATHSEP, map);
      setDeviceInfoProperty(pstmt, 9, DevMod.KEY_SEP, map);
      setDeviceInfoProperty(pstmt, 10, DevMod.KEY_NL, map);
      setDeviceInfoProperty(pstmt, 11, DevMod.KEY_TMP, map);
      setDeviceInfoProperty(pstmt, 12, DevMod.KEY_DIR, map);
      setDeviceInfoProperty(pstmt, 13, DevMod.KEY_PROGENV, map);
      setDeviceInfoProperty(pstmt, 14, DevMod.KEY_BIN, map);
      setDeviceInfoProperty(pstmt, 15, DevMod.KEY_MUDURL, map);
      setDeviceInfoProperty(pstmt, 16, DevMod.KEY_MODULES, map);

      Timestamp created = new Timestamp(Calendar.getInstance().getTimeInMillis());
      pstmt.setTimestamp(17, created);

      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }


  /**
   * Removes the device info record from the database.
   *
   * @param ds   Datasource instance.
   * @param guid The guid of the device.
   */
  public void removeDeviceInfo(DataSource ds, String guid) {
    String sql = "DELETE FROM DEVICE_MODULE_INFO WHERE GUID = ?";
    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, guid);
      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }


  /**
   * Get the deviceinfo from the Database.
   *
   * @param ds   Datasource instance.
   * @param guid The guid of the device.
   * @return A Composite map containing DevMod name value pairs.
   */
  public Composite getDeviceInfo(DataSource ds, String guid) {
    Composite map = Composite.newMap();
    // Read the file content whose hash needs to be calculated.
    String sql = "SELECT "
        + "DEVICE_TYPE,"
        + "MODULES,"
        + "FILE_NAME_SEPARATOR, "
        + "OS_NAME, "
        + "OS_VERSION,  "
        + "OS_ARCH "
        + "FROM DEVICE_MODULE_INFO WHERE GUID = ?";
    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, guid);
      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          map.set(DevMod.KEY_DEVICE, rs.getString(1));
          map.set(DevMod.KEY_MODULES, rs.getString(2));
          map.set(DevMod.KEY_SEP, rs.getString(3));
          map.set(DevMod.KEY_OS, rs.getString(4));
          map.set(DevMod.KEY_VERSION, rs.getString(5));
          map.set(DevMod.KEY_ARCH, rs.getString(6));

        }
      }
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
    return map;
  }


  /**
   * Gets the list of system resources to return to the device.
   *
   * @param ds      Datasource instance.
   * @param guid    The guid of the device.
   * @param devInfo A Map of keys returned from the DevMod.
   * @return A Composite array of resources id an their types.
   */
  public Composite getSystemResources(DataSource ds,
      String guid,
      Composite devInfo) {

    Composite resList = Composite.newArray();
    String deviceType = devInfo.getAsString(DevMod.KEY_DEVICE);
    String osName = devInfo.getAsString(DevMod.KEY_OS);
    String osVersion = devInfo.getAsString(DevMod.KEY_VERSION);
    String archType = devInfo.getAsString(DevMod.KEY_ARCH);

    String sql = "SELECT RESOURCE_ID, CONTENT_TYPE_TAG, UPDATED "
        + "FROM SYSTEM_MODULE_RESOURCE "
        + "WHERE (GUID_TAG = ? OR GUID_TAG IS NULL ) AND "
        + "(DEVICE_TYPE_TAG = ? OR DEVICE_TYPE_TAG IS NULL ) AND "
        + "(OS_NAME_TAG  = ? OR OS_NAME_TAG IS NULL ) AND "
        + "(OS_VERSION_TAG = ? OR OS_VERSION_TAG IS NULL ) AND "
        + "(ARCHITECTURE_TAG = ? OR ARCHITECTURE_TAG IS NULL ) AND "
        + "(CONTENT_TYPE_TAG = 'fdo_sys:filedesc' "
        + "OR CONTENT_TYPE_TAG = 'fdo_sys:exec' "
        + "OR CONTENT_TYPE_TAG = 'fdo_sys:active' "
        + "OR CONTENT_TYPE_TAG = 'fdo_sys:ismore' "
        + "OR CONTENT_TYPE_TAG = 'fdo_sys:isdone') "
        + "ORDER BY PRIORITY ASC";
    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, guid);
      pstmt.setString(2, deviceType);
      pstmt.setString(3, osName);
      pstmt.setString(4, osVersion);
      pstmt.setString(5, archType);
      try (ResultSet rs = pstmt.executeQuery()) {
        while (rs.next()) {
          Composite resItem = Composite.newArray();
          resItem.set(Const.FIRST_KEY, rs.getString(1));
          resItem.set(Const.SECOND_KEY, rs.getString(2));
          resItem.set(Const.THIRD_KEY, rs.getString(3));
          resList.set(resList.size(), resItem);
        }
      }
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
    return resList;
  }

  /**
   * Gets the Content of a resource.
   *
   * @param ds         Datasource instance.
   * @param resourceId The resource id.
   * @return The content as a byte array.
   */
  public byte[] getSystemResourceContent(DataSource ds,
      String resourceId) {

    String sql = "SELECT "
        + "CONTENT "
        + "FROM SYSTEM_MODULE_RESOURCE "
        + "WHERE (RESOURCE_ID = ? AND CONTENT IS NOT NULL) OR "
        + "(RESOURCE_ID = (SELECT CONTENT_RESOURCE_TAG WHERE RESOURCE_ID = ?))";
    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, resourceId);
      pstmt.setString(2, resourceId);
      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          return rs.getBytes(1);

        }
      }
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
    throw new RuntimeException(new NoSuchElementException());
  }

  /**
   * The a byte range within the content of a resource.
   *
   * @param ds         Datasource instance.
   * @param resourceId The resource id.
   * @param start      The start byte of the range.
   * @param end        The last byte to return in the range.
   * @return The bytes at the specified range.
   */
  public byte[] getSystemResourceContentWithRange(DataSource ds,
      String resourceId,
      int start,
      int end) {
    String sql = "SELECT "
        + "LENGTH(CONTENT), "
        + "CONTENT, "
        + "FROM SYSTEM_MODULE_RESOURCE "
        + "WHERE (RESOURCE_ID = ? AND CONTENT IS NOT NULL) OR "
        + "(RESOURCE_ID = (SELECT CONTENT_RESOURCE_TAG WHERE RESOURCE_ID = ?))";

    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, resourceId);
      pstmt.setString(2, resourceId);
      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          int maxValue = rs.getInt(1);
          try (InputStream input = rs.getBinaryStream(2)) {
            if (start > 0) {
              input.skip(start);
            }
            int len = end - start;
            if ((start + len) > maxValue) {
              len = maxValue - start;
            }
            return input.readNBytes(len);
          }
        }
      }
    } catch (SQLException | IOException e) {
      throw new RuntimeException(e);
    }
    throw new RuntimeException(new NoSuchElementException());
  }

  /**
   * Gets the value of the FILE_NAME tag of the resource.
   *
   * @param ds         Datasource instance.
   * @param resourceId The resource id.
   * @return The value of the FILE_NAME tag.
   */
  public String getSystemResourcesFileName(DataSource ds, String resourceId) {
    String sql = "SELECT FILE_NAME_TAG "
        + "FROM SYSTEM_MODULE_RESOURCE "
        + "WHERE RESOURCE_ID = ?;";
    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {
      pstmt.setString(1, resourceId);
      try (ResultSet rs = pstmt.executeQuery()) {
        if (rs.next()) {
          return rs.getString(1);
        }
      }
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
    throw new RuntimeException(new NoSuchElementException());
  }

  /**
   * Removes customer keys entry corresponding to the customer ID.
   *
   * @param ds         Datasource
   * @param customerId customer ID
   */
  public void removeCustomer(DataSource ds, String customerId) {
    String sql = "DELETE FROM OWNER_CUSTOMERS WHERE CUSTOMER_ID = ?;";
    try (Connection conn = ds.getConnection();
        PreparedStatement pstmt = conn.prepareStatement(sql)) {

      pstmt.setString(1, customerId);
      pstmt.executeUpdate();
    } catch (SQLException e) {
      throw new RuntimeException(e);
    }
  }
}
