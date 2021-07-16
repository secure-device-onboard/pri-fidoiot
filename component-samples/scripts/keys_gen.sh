#!/bin/bash
#
# Copyright 2021 Intel Corporation
# SPDX-License-Identifier: Apache 2.0
#
# Summary:
#    keys_gen.sh script is mainly implemented to generate a new keystores,
#    device keys, ssl keystore, ssl truststore for all PRI components to
#    onboard PRI device or any other device with the fresh keys.
#
# List of output files:
#
# PRI FIDOIOT component output files. xxx -> [manufacturer, owner, reseller]
#
# /path/to/root/of/pri/binaries/creds/xxx_pub_keys.pem  -> Public Keys file
# /path/to/root/of/pri/binaries/creds/xxx_pub_keys.hash -> Hash file
# /path/to/root/of/pri/binaries/creds/xxx_keystore.p12  -> Keystore file
#
# TLS truststore and keystore output files.
#
# /path/to/root/of/pri/binaries/creds/ssl.p12    -> SSL Keystore
# /path/to/root/of/pri/binaries/creds/truststore -> Truststore
#
# PRI Device pem output files. xxx -> [256, 384]
# /path/to/root/of/pri/binaries/creds/device_ecxxx_cert.pem    -> Device certificate
# /path/to/root/of/pri/binaries/creds/device_ecxxx_private.key -> Device private key
#
# Commands we use for execution:
# 1) ./keys_gen.sh
#   Gives a message to make use of -h option
# 2) ./keys_gen.sh -h
#   Displays the usage message with all available options
# 3) ./keys_gen.sh /path/to/root/of/pri/binaries
#   Generates new credentials and update all destination paths
# 4) ./keys_gen.sh /path/to/root/of/pri/binaries -m
#   Generates new credentials for manufacturer and update all files within manufacturer component
# 5) ./keys_gen.sh /path/to/root/of/pri/binaries -o
#   Generates new credentials for owner and update all files within owner component
# 6) ./keys_gen.sh /path/to/root/of/pri/binaries -r
#   Generates new credentials for reseller and update all files within reseller component
# 7) ./keys_gen.sh /path/to/root/of/pri/binaries -t
#   Generates new ssl keystore and its truststore for signing and update all destination paths
# 8) ./keys_gen.sh /path/to/root/of/pri/binaries -d
#   Generates new device keys and updates all files.
# 9) ./keys_gen.sh /path/to/root/of/pri/binaries <combination of options>
#   Generates the new credentials based upon the options that we provide in a combination
#
# ToDo List:
# 1) Hashes update in the file component-samples/demo/rv/config.properties should reflect in RV database
# 2) Removing the existing credentials from the source code
# 3) Updating the code to read from the newly generated keys by overwriting the default keys
#
# Validated Scenarios with these new set of credentials:
# 1) Basic sanity testcase (e2e)
# 2) Resale testcase
# 3) Reuse testcase
# 4) SVI testcase
# 5) RV-ByPass testcase
# 6) Multiple RV-Info testcase
# 7) MTU testcase
# 8) Basic e2e testcase with HTTPS

shopt -s extglob
set -e

# Usage message to be displayed whenever we provide wrong inputs
usage()
{
  echo -e "Usage:
  $0 <absolute_path_of_pri_components> <OPTIONS>\n

  absolute_path_of_pri_components => /path/to/root/of/pri/binaries

  OPTIONS:
    -m => To create manufacturer keystore
    -o => To create owner keystore
    -r => To create reseller keystore
    -t => To create TLS keystore
    -d => To create device pem files
    -h => Prints help message\n
  NOTE: Order of arguments passing shouldn't change"
}

# Update the component creds.env file with the new credentials
pass_update_env_files()
{
  # Arg1: Path of Component
  comp=$1

  # Arg2: Environment statement that needs to be added
  statement=$2

  mkdir -p ${comp}
  echo ${statement} >> ${comp}/creds.env
}

# Generation of keystore with rsa, ec256 and ec384 keys as shown below
# ---------------------------------------------------------------------------
# Private key    -> Public Key    -> Certificate -> P12 Key   -> P12 Keystore
# ---------------------------------------------------------------------------
# rsa_priv_key   -> rsa_pub_key   -> rsa_cert    -> rsa.p12   -> keystore.p12
# ec256_priv_key -> ec256_pub_key -> ec256_cert  -> ec256.p12 -> keystore.p12
# ec384_priv_key -> ec384_pub_key -> ec384_cert  -> ec384.p12 -> keystore.p12
# ---------------------------------------------------------------------------
# Merging the above generated public keys into one file with respective to single pri component
# Redirecting the randomly generated password into /path/to/root/of/pri/binaries/creds/pri_keys.pass

# Generate hash of public key (takes certificate as input)
# Certificate -> Encrypted .der file -> Hash
# Redirect hashes to the corresponding output file
generate_hash()
{
  # Arg1: Certificate file
  certfile=$1

  # Arg2: Output hash file
  hashfile=$2

  # Generate public key hash
  openssl x509 -in $certfile -pubkey -noout | openssl enc -base64 -d > public.der
  cat public.der | openssl dgst -sha256 | awk '/s/{print toupper($2)}' > $hashfile
 
  rm -f public.der
}

# Generate RSA keypair
generate_keypair_rsa()
{
  # Arg1: Curve name
  keylen=$1

  # Arg2: Keystore password
  pass=$2

  # Generate RSA2048 Keys and include them in the keystore
  openssl genrsa -F4 -out private.key ${keylen} > /dev/null 2>&1

  openssl rsa -in private.key -outform PEM -pubout \
    -out public.key > /dev/null 2>&1

  openssl req -x509 -key private.key -out cert.pem -days 3650 -batch

  openssl pkcs12 -export -in cert.pem -inkey private.key -name rsa${keylen} \
    -out rsa${keylen}.p12 -password pass:${pass}

  # Generate public key hash
  generate_hash cert.pem rsa${keylen}_public.hash

  cp public.key rsa${keylen}_public.key
}

# Generate EC keypair
generate_keypair_ec()
{
  # Arg1: Curve name
  keylen=$1

  # Arg2: Keystore password
  pass=$2

  if [ $keylen == "256" ]; then
    curve=prime256v1
  else
    curve=secp384r1
  fi

  # Remove temporary files form last call
  rm -f private.key public.key cert.pem ec${keylen}.p12

  # Keys Generations
  openssl ecparam -name $curve -genkey -noout -out private.key > /dev/null 2>&1

  openssl ec -in private.key -pubout -out public.key > /dev/null 2>&1

  openssl req -x509 -key private.key -out cert.pem -days 3650 -batch

  openssl pkcs12 -export -in cert.pem -inkey private.key -name ec${keylen} \
    -out ec${keylen}.p12 -password pass:${pass}

  # Generate public key hash
  generate_hash cert.pem ec${keylen}_public.hash

  cp public.key ec${keylen}_public.key
}

# Import one keystore into another keystore
import_keystore()
{
  # Arg1: Destination keystore
  dest=$1

  # Arg2: Source keystore
  src=$2

  # Arg3: Keystore password (both src and dest keystore have same passwrod)
  pass=$3

  keytool -importkeystore -srckeystore ${src} -srcstorepass ${pass} \
    -destkeystore ${dest} -deststorepass ${pass} \
    -deststoretype pkcs12 -noprompt > /dev/null 2>&1
}

generate_keystore()
{
  PASS_KEY=`openssl rand --base64 12 | tr -dc 0-9A-Za-z`

  rm -f keystore.p12 ec256.p12 ec384.p12 rsa2048.p12
  rm -f pub_keys.pem

  # RSA2048 Keys Generations
  generate_keypair_ec 256 ${PASS_KEY}
  generate_keypair_ec 384 ${PASS_KEY}
  generate_keypair_rsa 2048 ${PASS_KEY}

  # Import rsa2048, ec256, and ec384 p12 keystores to one p12 keystore
  import_keystore keystore.p12 ec256.p12 ${PASS_KEY}
  import_keystore keystore.p12 ec384.p12 ${PASS_KEY}
  import_keystore keystore.p12 rsa2048.p12 ${PASS_KEY}

  # Verify the keys from p12 keystore
  keytool -list -keystore keystore.p12 -storepass ${PASS_KEY} > /dev/null 2>&1

  # Creating a keys.pem files
  cat ec256_public.key | tee pub_keys.pem > /dev/null
  cat ec384_public.key | tee -a pub_keys.pem > /dev/null
  cat rsa2048_public.key | tee -a pub_keys.pem > /dev/null

  cat ec256_public.hash | tee pub_keys.hash > /dev/null
  cat ec384_public.hash | tee -a pub_keys.hash > /dev/null
  cat rsa2048_public.hash | tee -a pub_keys.hash > /dev/null

  # Preserve necessary artifacts
  mv keystore.p12 ${1}_keystore.p12
  mv pub_keys.pem ${1}_pub_keys.pem
  mv pub_keys.hash ${1}_pub_keys.hash

  # Delete temporary files
  rm -f ec256.p12 ec384.p12 rsa2048.p12
  rm -f ec256_public.key ec384_public.key rsa2048_public.key
  rm -f ec256_public.hash ec384_public.hash rsa2048_public.hash

  # Redirecting password into one file
  echo "${PASS_KEY}" > ${1}_keystore.pass
}

# Calling the generate_keystore functions generate keystores and hashes
# Updating the existing component keystores with the newly generated keystores
# Updating the corresponding passwords in all the component environment files
# Logging the path of the generated keystores or hashes or passwords
generate_component_keys()
{
  # Cleaning all component keys that only exists in order to regenerate fresh keys
  if [[ -f ${1}_keystore.p12 ]]; then
    rm -rf ${1}*
  fi

  printf "%.40s" "Generating ${1}_keystore.p12 ..................."

  # Generating keystores and hashes of the component
  generate_keystore $1

  # Copying the keystores to the destination paths
  mkdir -p $CREDS_PATH/${1}
  cp ${1}_keystore.p12 $CREDS_PATH/${1}/${1}_keystore.p12

  # Updating the password in the component environment file
  pass_update_env_files $CREDS_PATH/${1} "${1}_keystore_password=${PASS_KEY}"

  # Logging the path of component hashes and it password
  printf " successful\n"
}

# Updating all component key hashes to the RV config.properties
prepare_rv_config()
{
  printf "%.40s" "Updating rv/config.properties ..................."
  # Capturing all component keystore hashes into one environmental variable HASHES
  for i in *.hash; do
    if [[ $i =~ ".hash" ]]; then
      sed -n '1,3'p $i | tee -a all_hashes.txt > /dev/null
    fi
  done
  sed -i "1,$((`cat all_hashes.txt | wc -l`-1))s/$/,\\\\/g" all_hashes.txt
  HASHES=`cat all_hashes.txt`; rm -rf all_hashes.txt;

  # Updating the RV config.properties file with the new hashes of 3 components (mfg, own, & reseller)
  mkdir -p $CREDS_PATH/rv
  printf "guid.denylist=\n\n" > $CREDS_PATH/rv/config.properties
  printf "allowlist.publickeyhash=\n\n" >> $CREDS_PATH/rv/config.properties
  printf "denylist.publickeyhash=\n" >> $CREDS_PATH/rv/config.properties

  ALLOW_LINE=`grep -rn "allowlist.publickeyhash" $CREDS_PATH/rv/config.properties | cut -d ':' -f 1`
  DENY_LINE=`grep -rn "denylist.publickeyhash" $CREDS_PATH/rv/config.properties | cut -d ':' -f 1`
  sed -i "s/allowlist.publickeyhash\=.*/allowlist.publickeyhash\=\\\\/g" $CREDS_PATH/rv/config.properties
  sed -i "$((ALLOW_LINE+1)),$((DENY_LINE-1))d" $CREDS_PATH/rv/config.properties
  sed -i "$((ALLOW_LINE)) a ${HASHES}" $CREDS_PATH/rv/config.properties;
  sed -i "s/,/,\\\\/g" $CREDS_PATH/rv/config.properties;

  printf " successful\n"
}

# Generating new device keys and updating it into the device.pem file
device_pem_files()
{
  mkdir -p $CREDS_PATH/device

  printf "%.40s" "Generating device_ec256.pem ..................."
  generate_keypair_ec 256
  cat cert.pem > $CREDS_PATH/device/device_ec256.pem
  cat private.key >> $CREDS_PATH/device/device_ec256.pem
  printf " successful\n"

  printf "%.40s" "Generating device_ec384.pem ..................."
  generate_keypair_ec 384
  cat cert.pem > $CREDS_PATH/device/device_ec384.pem
  cat private.key >> $CREDS_PATH/device/device_ec384.pem
  printf " successful\n"

  cp $CREDS_PATH/device/device_ec256.pem $CREDS_PATH/device/device.pem
}

# Generation of TLS keystore and truststore for signing purpose
# Updating all the keystores and truststores in the required destination paths
# Updating the ssl-keystore-password that is generated randomly in all the component environment files
generate_tls_keystore()
{
  # Cleaning all existing component keys to regenerate fresh keys
  rm -f ssl.p12 ssl.pass truststore

  printf "%.40s" "Generating ssl.p12 and truststore ..................."

  # TLS keystore and truststore creation steps
  if=$(ip route | grep default | sed -e "s/^.*dev.//" -e "s/.proto.*//")
  ip=$(ip addr | grep inet | grep " $if" | cut -d' ' -f6 | cut -d'/' -f1)
  openssl req \
    -x509 \
    -newkey rsa:2048 \
    -sha256 \
    -days 3560 \
    -nodes \
    -keyout tls.key \
    -out tls.crt \
    -subj '/CN=fdo' \
    -extensions san \
    -config <( \
    echo '[req]'; \
    echo 'distinguished_name=req'; \
    echo '[san]'; \
    echo 'subjectAltName=DNS:localhost,IP.1:127.0.0.1,IP.2:'${ip}) > /dev/null 2>&1

  export SSL_PASS=`openssl rand --base64 8 | tr -dc 0-9A-Za-z`
  openssl pkcs12 -export -in tls.crt -inkey tls.key -out ssl.p12 -password pass:${SSL_PASS}
  keytool -import -alias fdo -file tls.crt -storetype PKCS12 -keystore truststore \
    -storepass ${SSL_PASS} -noprompt > /dev/null 2>&1
  echo "${SSL_PASS}" > ssl.pass

  # TODO: Remove following chmod call
  chmod 0755 ssl.p12

  # Copying the ssl keystore and truststores to the destination paths
  for comp in "manufacturer" "rv" "owner" "reseller" "aio"; do
    mkdir -p $CREDS_PATH/$comp/certs/
    cp ssl.p12 $CREDS_PATH/$comp/certs/
    pass_update_env_files $CREDS_PATH/$comp "${comp}_ssl_keystore-password=${SSL_PASS}"
  done

  for comp in "owner" "aio"; do
    mkdir -p $CREDS_PATH/$comp/certs
    cp truststore $CREDS_PATH/$comp/certs/
    pass_update_env_files $CREDS_PATH/$comp "ssl_truststore_password=${SSL_PASS}"
  done

  printf " successful\n"

  rm -rf tls.???
}

# Copy only if source file exists
# Create destination folder if it doesn't exist
# Copy to destination with given filename
copy_failsafe_rename()
{
  # Arg1: Source file
  srcfile=$1

  # Arg2: Destination directory
  destdir=$2

  # Arg3: Destination file
  destfile=$3

  if [ -e $srcfile ]; then
    mkdir -p $destdir
    cp $srcfile $destdir/$destfile
  fi
}

# Create a folder if the destination folder doesn't exist
copy_failsafe()
{
  copy_failsafe_rename $1 $2 $1
}

misc_copy()
{
  printf "%.40s" "Copying files to components ..................."

  # Copy owner_pub_keys.pem
  copy_failsafe_rename owner_pub_keys.pem $CREDS_PATH/aio/resources owner_customer1.pem
  copy_failsafe owner_pub_keys.pem $CREDS_PATH/manufacturer
  copy_failsafe owner_pub_keys.pem $CREDS_PATH/owner
  copy_failsafe owner_pub_keys.pem $CREDS_PATH/reseller

  # Copy reseller_pub_keys.pem
  copy_failsafe reseller_pub_keys.pem $CREDS_PATH/manufacturer
  copy_failsafe_rename reseller_pub_keys.pem $CREDS_PATH/owner owner2_pub_keys.pem

  if [ -e manufacturer_keystore.p12 ]; then
    copy_failsafe manufacturer_keystore.p12 $CREDS_PATH/aio
    PASS_KEY=$(cat manufacturer_keystore.pass)
    pass_update_env_files $CREDS_PATH/aio "manufacturer_keystore_password=${PASS_KEY}"
  fi

  if [ -e owner_keystore.p12 ]; then
    copy_failsafe owner_keystore.p12 $CREDS_PATH/aio
    PASS_KEY=$(cat owner_keystore.pass)
    pass_update_env_files $CREDS_PATH/aio "owner_keystore_password=${PASS_KEY}"
  fi

  printf " successful\n"
}

# Main functionality is defined in this function
start_generation()
{
  arr=($*)
  components=("manufacturer" "owner" "reseller")
  if [[ $# == 0 ]]; then
    echo "For help, provide -h to the script"; exit 1;
  elif [[ $* =~ "-h" ]]; then
    usage; exit 1;
  elif [[ $# == 1 ]]; then
    arr+=('default')
  fi
  for option in ${arr[@]:1}; do
    case $option in
      "-m")
        generate_component_keys "manufacturer"
        prepare_rv_config
        misc_copy
        ;;
      "-o")
        generate_component_keys "owner"
        prepare_rv_config
        misc_copy
        ;;
      "-r")
        generate_component_keys "reseller"
        prepare_rv_config
        misc_copy
        ;;
      "-t")
        generate_tls_keystore
        ;;
      "-d")
        device_pem_files
        ;;
      *)
        for i in ${components[@]}; do
          if [[ "${components[@]}" =~ "$i" ]]; then
            generate_component_keys $i
          fi
        done
        prepare_rv_config;
        generate_tls_keystore
        device_pem_files
        misc_copy
        break;;
    esac
  done
}

# Environmental variables
if [ $# -lt 1 ]; then
  usage
  exit
fi

COMP_PATH=$(realpath $1)
CREDS_PATH=$COMP_PATH/creds
CERTS_PATH=$CREDS_PATH/tmp

# Change work directory to CERTS_PATH
rm -rf $CERTS_PATH $CREDS_PATH
mkdir -p $CERTS_PATH $CREDS_PATH

cd $CERTS_PATH

start_generation $*

# Remove temporary files
rm -rf $CERTS_PATH
