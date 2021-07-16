#!/bin/sh
#
# Copyright 2020 Intel Corporation
# SPDX-License-Identifier: Apache 2.0

# LOG4J2 configuration file
LOG_CONFIG="-Dlog4j.configurationFile=${log4j_configuration_file}"

# Sample script that configures the softHSM and inserts the manufacturer keys

# Initialize softHSM token with SO PIN and User pin.
softhsm2-util --init-token --slot 0 --label "manufacturer-Token" --so-pin $manufacturer_keystore_password --pin $manufacturer_keystore_password

# Import manufacturer keys into PKCS11 keystore
keytool -importkeystore -deststorepass $manufacturer_keystore_password -destkeystore NONE -srckeystore $manufacturer_keystore -deststoretype PKCS11 -srcstoretype PKCS12 -srcstorepass $manufacturer_keystore_password

# Start the manufacturer service
exec java ${LOG_CONFIG} -jar /home/manufacturer/manufacturer.jar
