// Copyright 2020 Intel Corporation
// SPDX-License-Identifier: Apache 2.0

package org.fidoalliance.fdo.api;

import java.io.IOException;
import java.util.stream.Collectors;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.sql.DataSource;
import org.fidoalliance.fdo.protocol.Const;
import org.fidoalliance.fdo.storage.OwnerDbManager;

public class OwnerSviSettingsServlet extends HttpServlet {

  private static final String SETTINGS_DEVICE_MTU = "devicemtu";
  private static final String SETTINGS_OWNER_THRESHOLD = "ownerthreshold";
  private static final String SETTINGS_WGET_MODE_CONTENT_VERIFICATION =
      "wgetModContentVerification";
  private static final String SETUPINFO_ARRAY_DELIMETER = ",";
  private static final String SETUPINFO_VALUE_DELIMETER = ":=";

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {

    if (req.getContentType().compareToIgnoreCase("application/text") != 0) {
      resp.setStatus(Const.HTTP_UNSUPPORTED_MEDIA_TYPE);
      return;
    }

    try {
      String requestBody = req.getReader().lines().collect(Collectors.joining());

      /* Request format:
      devicemtu:=<mtusettingze>,
      ownerthreshold:=<thresholdmtu>,
      wgetModContentVerification:=<boolean>
       */
      if (requestBody != null) {
        DataSource ds = (DataSource) getServletContext().getAttribute("datasource");
        OwnerDbManager ownerDbManager = new OwnerDbManager();

        String[] to2Settings = requestBody.split(SETUPINFO_ARRAY_DELIMETER);
        if (to2Settings.length > 2) {
          getServletContext().log("Invalid to2Settings request has been provided.");
          resp.setStatus(400);
          return;
        }
        int deviceMtu = 0;
        int ownerThresholdMtu = 0;
        for (String setupInfo : to2Settings) {
          String[] setting = setupInfo.split(SETUPINFO_VALUE_DELIMETER);
          if (setting.length == 2) {
            switch (setting[0]) {
              case SETTINGS_DEVICE_MTU:
                deviceMtu = Integer.parseInt(setting[1]);
                getServletContext().log("Updating Device MTU for TO2 Settings");
                ownerDbManager.updateMtu(ds, "DEVICE_SERVICE_INFO_MTU_SIZE", deviceMtu);
                break;
              case SETTINGS_OWNER_THRESHOLD:
                ownerThresholdMtu = Integer.parseInt(setting[1]);
                if (ownerThresholdMtu < Const.SERVICE_INFO_MTU_MIN_SIZE) {
                  getServletContext()
                          .log("Received value below the minimum MTU size. "
                              + "Updating Owner Threshold to minimum MTU size of 256 bytes");
                  ownerThresholdMtu = Const.SERVICE_INFO_MTU_MIN_SIZE;
                } else if (ownerThresholdMtu > Const.OWNER_THRESHOLD_DEFAULT_MTU_SIZE) {
                  getServletContext()
                          .log("Received value above the maximum MTU size. "
                              + "Updating Owner Threshold to default MTU size of 8192 bytes");
                  ownerThresholdMtu = Const.OWNER_THRESHOLD_DEFAULT_MTU_SIZE;
                }
                getServletContext().log("Updating Owner Threshold MTU for TO2 Settings");
                ownerDbManager.updateMtu(ds, "OWNER_MTU_THRESHOLD", ownerThresholdMtu);
                break;
              default:
                break;
            }
          } else {
            getServletContext().log("Invalid settings request has been provided.");
            resp.setStatus(400);
            return;
          }
        }
      }
    } catch (Exception exp) {
      getServletContext().log("Error occurred while updating TO2 settings " + exp.getMessage());
      resp.setStatus(Const.HTTP_INTERNAL_SERVER_ERROR);
    }
  }
}
