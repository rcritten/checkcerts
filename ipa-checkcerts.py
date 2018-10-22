#
# Copyright (C) 2018 FreeIPA Contributors see COPYING for license
#

from __future__ import absolute_import

import argparse
import base64
import datetime
import grp
import logging
import os
import pwd
import sys
import tempfile
import gssapi
from six import string_types
from ipalib import api
from ipalib import errors
from ipalib import x509
from ipalib.install import certstore
from ipalib.install.kinit import kinit_keytab
from ipalib.install import certmonger
from ipaplatform.paths import paths
from ipaserver.install import installutils
from ipaserver.install import certs
from ipaserver.install import cainstance
from ipaserver.install import dsinstance
from ipaserver.install import httpinstance
from ipaserver.plugins import ldap2
from ipapython.certdb import unparse_trust_flags
from ipapython.dn import DN
from ipapython import ipautil
from ipapython import dogtag
from ipapython.ipa_log_manager import log_mgr
from ipapython import ipa_log_manager
from ipapython import version
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import ObjectIdentifier
try:
    from ipapython.directivesetter import get_directive
except ImportError:
    from ipaserver.install.installutils import get_directive
from pyasn1_modules.rfc2459 import Name
from pyasn1.codec.der.decoder import decode
try:
    from ipapython.dn import ATTR_NAME_BY_OID
except ImportError:
    from ipapython.dn import _ATTR_NAME_BY_OID as ATTR_NAME_BY_OID

parser = argparse.ArgumentParser(
    prog='ipa-checkcerts',
    description='IPA certificate health checker'
)

parser.add_argument(
    '--debug',
    action='store_true',
    help='Enable IPA API debugging output'
)
parser.add_argument(
    '--verbose',
    action='store_true',
    help='Verbose mode'
)


if version.NUM_VERSION < 40700:
    KEYDB = 'key3.db'
    CERTDB = 'cert8.db'
    SECDB = 'secmod.db'
    logger = log_mgr.get_logger(__name__)
else:
    KEYDB = 'key4.db'
    CERTDB = 'cert9.db'
    SECDB = 'pkcs11.txt'
    logger = logging.getLogger(os.path.basename(__file__))


def load_pem_certificate(cert):
    """Abstract load PEM certificate by IPA version"""
    if version.NUM_VERSION < 40600:
        return x509.load_certificate(cert, x509.PEM)
    elif version.NUM_VERSION < 40700:
        return x509.load_pem_x509_certificate(cert)
    else:
        return x509.load_pem_x509_certificate(bytes(cert, 'utf-8'))


def load_der_certificate(cert):
    """Abstract load DER certificate by IPA version"""
    if version.NUM_VERSION < 40600:
        return x509.load_certificate(cert, x509.DER)
    else:
        return x509.load_der_x509_certificate(cert)


def der_to_subject(der):
    """Convert Name() ASN.1 into a DN type"""
    name, _ = decode(der, asn1Spec=Name())

    subject = DN()

    for item in name.getComponentByPosition(0):
        data = item.getComponentByPosition(0)

        rdn = data.getComponentByPosition(0).prettyPrint()
        value = data.getComponentByPosition(1).asOctets()[2:].decode('utf-8')

        subject += (DN((ATTR_NAME_BY_OID[ObjectIdentifier(rdn)], value)))

    return subject


def is_ipa_issued_cert(api, cert):
    """
    Compatibility function since 4.5 and 4.6 can only check certs
    in an NSS database.

    Return True if the certificate has been issued by IPA

    Note that this method can only be executed if the api has been
    initialized.

    :param api: The pre-initialized IPA API
    :param cert: The IPACertificate certificiate to test
    """
    cacert_subject = certstore.get_ca_subject(
        api.Backend.ldap2,
        api.env.container_ca,
        api.env.basedn)

    return DN(cert.issuer) == cacert_subject


class certcheck(object):
    """
    Checks out certificate stuff
    """

    def __init__(self):
        self.failures = []
        self.warnings = []
        self.service = None
        self.serverid = None
        self.ca = None
        self.ds = None
        self.http = None
        self.conn = None

    def failure(self, msg):
        self.failures.append(msg)
        logger.debug('FAIL: %s', msg)

    def warning(self, msg):
        self.warnings.append(msg)
        logger.debug('WARN: %s', msg)

    def validate_openssl(self, file):
        """Call out to openssl to verify a certificate against global chain"""
        args = [paths.OPENSSL, "verify", file]

        try:
            result = ipautil.run(args)
        except ipautil.CalledProcessError as e:
            self.failure('Validation of %s failed: %s'
                         % (file, e))

    def run(self):
        """Execute the tests"""

        api.Backend.ldap2.connect()

        self.serverid = installutils.realm_to_serverid(api.env.realm)

        self.ca = cainstance.CAInstance(api.env.realm,
                                        host_name=api.env.host)
        self.http = httpinstance.HTTPInstance()
        self.ds = dsinstance.DsInstance()

        self.conn = api.Backend.ldap2

        logger.info("Check CA status")
        self.check_ca_status()

        logger.info("Check tracking")
        self.check_tracking()

        logger.info("Check NSS trust")
        self.check_trust()

        logger.info("Check dates")
        self.check_dates()

        logger.info("Checking certificates in CS.cfg")
        self.check_cs_cfg()

        logger.info("Comparing certificates to requests in LDAP")
        self.compare_requests()

        logger.info("Checking RA certificate")
        self.check_ra_cert()

        logger.info("Checking authorities")
        self.check_ipa_to_cs_authorities()
        self.check_cs_to_ipa_authorities()

        logger.info("Checking host keytab")
        self.check_hostkeytab()

        logger.info("Validating certificates")
        self.validate_certs()

        logger.info("Checking renewal master")
        self.check_renewal_master()

        logger.info("End-to-end cert API test")
        self.cert_api_test()

        logger.info("Checking permissions and ownership")
        self.check_permissions()

        if self.conn is not None and self.conn.isconnected():
            self.conn.disconnect()

        if self.failures:
            logger.info("Failures:")
            for f in self.failures:
                logger.info(f)
        else:
            logger.info("All checks passed")

        if self.warnings:
            logger.info("Warnings:")
            for f in self.warnings:
                logger.info(f)

        return self.failures != []

    def get_requests(self):
        """Get certmonger tracking requests"""

        # TODO: put this in some central place for here and for
        #       ipaserver/install/server/upgrade.py

        template = paths.CERTMONGER_COMMAND_TEMPLATE

        requests = [
            {
                'cert-file': paths.RA_AGENT_PEM,
                'key-file': paths.RA_AGENT_KEY,
                'ca-name': 'dogtag-ipa-ca-renew-agent',
                'cert-presave-command': template % 'renew_ra_cert_pre',
                'cert-postsave-command': template % 'renew_ra_cert',
            },
        ]

        ca_requests = [
            {
                'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                'cert-nickname': 'auditSigningCert cert-pki-ca',
                'ca-name': 'dogtag-ipa-ca-renew-agent',
                'cert-presave-command': template % 'stop_pkicad',
                'cert-postsave-command': (
                    template %
                    'renew_ca_cert "auditSigningCert cert-pki-ca"'),
            },
            {
                'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                'cert-nickname': 'ocspSigningCert cert-pki-ca',
                'ca-name': 'dogtag-ipa-ca-renew-agent',
                'cert-presave-command': template % 'stop_pkicad',
                'cert-postsave-command': (
                    template %
                    'renew_ca_cert "ocspSigningCert cert-pki-ca"'),
            },
            {
                'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                'cert-nickname': 'subsystemCert cert-pki-ca',
                'ca-name': 'dogtag-ipa-ca-renew-agent',
                'cert-presave-command': template % 'stop_pkicad',
                'cert-postsave-command': (
                    template %
                    'renew_ca_cert "subsystemCert cert-pki-ca"'),
            },
            {
                'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                'cert-nickname': 'caSigningCert cert-pki-ca',
                'ca-name': 'dogtag-ipa-ca-renew-agent',
                'cert-presave-command': template % 'stop_pkicad',
                'cert-postsave-command': (
                    template % 'renew_ca_cert "caSigningCert cert-pki-ca"'),
                'template-profile': None,
            },
            {
                'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                'cert-nickname': 'Server-Cert cert-pki-ca',
                'ca-name': 'dogtag-ipa-ca-renew-agent',
                'cert-presave-command': template % 'stop_pkicad',
                'cert-postsave-command': (
                    template %
                    'renew_ca_cert "Server-Cert cert-pki-ca"'),
            },
        ]

        if self.ca.is_configured():
            db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
            for nickname, _trust_flags in db.list_certs():
                if nickname.startswith('caSigningCert cert-pki-ca '):
                    requests.append(
                        {
                            'cert-database': paths.PKI_TOMCAT_ALIAS_DIR,
                            'cert-nickname': nickname,
                            'ca-name': 'dogtag-ipa-ca-renew-agent',
                            'cert-presave-command': template % 'stop_pkicad',
                            'cert-postsave-command':
                                (template % ('renew_ca_cert "%s"' % nickname)),
                            'template-profile': 'caCACert',
                        }
                    )

        if self.ca.is_configured():
            requests += ca_requests

        # Check the http server cert if issued by IPA
        if version.NUM_VERSION >= 40700:
            cert = x509.load_certificate_from_file(paths.HTTPD_CERT_FILE)
            if is_ipa_issued_cert(api, cert):
                requests.append(
                    {
                        'cert-file': paths.HTTPD_CERT_FILE,
                        'key-file': paths.HTTPD_KEY_FILE,
                        'ca-name': 'IPA',
                        'cert-postsave-command': template % 'restart_httpd',
                    }
                )
        else:
            http_nickname = self.http.get_mod_nss_nickname()
            http_db = certs.CertDB(api.env.realm, nssdir=paths.HTTPD_ALIAS_DIR)
            if http_db.is_ipa_issued_cert(api, http_nickname):
                requests.append(
                    {
                        'cert-database': paths.HTTPD_ALIAS_DIR,
                        'cert-nickname': http_nickname,
                        'ca-name': 'IPA',
                        'cert-postsave-command': template % 'restart_httpd',
                        }
                    )

        # Check the ldap server cert if issued by IPA
        ds_nickname = self.ds.get_server_cert_nickname(self.serverid)
        ds_db_dirname = dsinstance.config_dirname(self.serverid)
        ds_db = certs.CertDB(api.env.realm, nssdir=ds_db_dirname)
        if ds_db.is_ipa_issued_cert(api, ds_nickname):
            requests.append(
                {
                    'cert-database': ds_db_dirname[:-1],
                    'cert-nickname': ds_nickname,
                    'ca-name': 'IPA',
                    'cert-postsave-command':
                        '%s %s' % (template % 'restart_dirsrv', self.serverid),
                }
            )

        # Check the KDC cert if issued by IPA
        cert = x509.load_certificate_from_file(paths.KDC_CERT)
        if is_ipa_issued_cert(api, cert):
            requests.append(
                {
                    'cert-file': paths.KDC_CERT,
                    'key-file': paths.KDC_KEY,
                    'ca-name': 'IPA',
                    'cert-postsave-command':
                        template % 'renew_kdc_cert',
                }
            )

        return requests

    def check_ca_status(self):
        """GET status from dogtag to see if it is running"""
        try:
            status = dogtag.ca_status(api.env.host)
            logger.debug('The CA status is: %s' % status)
        except Exception as e:
            self.failure('CA is not running: %s' % e)

    def check_tracking(self):
        """Compare expected vs actual tracking configuration"""
        requests = self.get_requests()
        cm = certmonger._certmonger()

        ids = []
        all_requests = cm.obj_if.get_requests()
        for req in all_requests:
            request = certmonger._cm_dbus_object(cm.bus, cm, req,
                                                 certmonger.DBUS_CM_REQUEST_IF,
                                                 certmonger.DBUS_CM_IF, True)
            id = request.prop_if.Get(certmonger.DBUS_CM_REQUEST_IF,
                                     'nickname')
            ids.append(str(id))

        for request in requests:
            request_id = certmonger.get_request_id(request)
            try:
                if request_id is not None:
                    ids.remove(request_id)
            except ValueError as e:
                self.failure('Failure trying to remove % from '
                             'list: %s' % (request_id, e))

            if request_id is None:
                self.failure('Missing tracking for %s' % request)

        if ids:
            self.warning('Unknown certmonger ids: %s' % ','.join(ids))

    def check_trust(self):
        """Check the NSS trust flags"""
        expected_trust = {
            'ocspSigningCert cert-pki-ca': 'u,u,u',
            'subsystemCert cert-pki-ca': 'u,u,u',
            'auditSigningCert cert-pki-ca': 'u,u,Pu',
            'Server-Cert cert-pki-ca': 'u,u,u'
        }
        # TODO: external CA certs
        # TODO: unexpected certs

        if not self.ca.is_configured():
            logger.debug("No CA configured, skipping trust check")
            return

        db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
        for nickname, _trust_flags in db.list_certs():
            flags = unparse_trust_flags(_trust_flags)
            if nickname.startswith('caSigningCert cert-pki-ca'):
                expected = 'CTu,Cu,Cu'
            else:
                expected = expected_trust[nickname]
            if flags != expected:
                self.failure(
                    'Incorrect NSS trust for %s. Got %s expected %s'
                    % (nickname, flags, expected))

    def check_dates(self):
        """Check validity dates"""
        # TODO: make this configurable
        threshold = 7  # days

        requests = self.get_requests()

        now = datetime.datetime.utcnow()

        for request in requests:
            request_id = certmonger.get_request_id(request)

            if request_id is None:
                # The missing tracking is reported in check_tracking()
                continue
            nickname = request.get('cert-nickname')
            rawcert = certmonger.get_request_value(request_id, 'cert')
            cert = load_pem_certificate(str(rawcert))
            diff = cert.not_valid_after - now
            if diff.days < 0:  # TODO: this is false-positive generator
                self.failure("Certificate %s is expired" % nickname)
            elif diff.days < threshold:
                self.failure("Certificate %s is expiring soon"
                             % nickname)
            elif cert.not_valid_before > now:
                self.failure("Certificate %s is not valid yet"
                             % nickname)

    def check_cs_cfg(self):
        """Compare cert blob in NSS database to that stored in CS.cfg"""
        if not self.ca.is_configured():
            logger.debug("No CA configured, skipping CS config check")
            return

        blobs = {'auditSigningCert cert-pki-ca': 'ca.audit_signing.cert',
                 'ocspSigningCert cert-pki-ca': 'ca.ocsp_signing.cert',
                 'caSigningCert cert-pki-ca': 'ca.signing.cert',
                 'subsystemCert cert-pki-ca': 'ca.subsystem.cert',
                 'Server-Cert cert-pki-ca': 'ca.sslserver.cert'}

        db = certs.CertDB(api.env.realm, paths.PKI_TOMCAT_ALIAS_DIR)
        for nickname, _trust_flags in db.list_certs():
            val = get_directive(paths.CA_CS_CFG_PATH,
                                blobs[nickname], '=')
            if val is None:
                self.failure(
                    'Certificate %s not found in %s'
                    % (blobs[nickname], paths.CA_CS_CFG_PATH))
                continue
            cert = db.get_cert_from_db(nickname)
            if isinstance(cert, string_types):
                pem = cert
                pem = pem.replace('\r\n', '')
            else:
                pem = cert.public_bytes(Encoding.PEM).decode()
                pem = pem.replace('\n', '')
            pem = pem.replace('-----BEGIN CERTIFICATE-----', '')
            pem = pem.replace('-----END CERTIFICATE-----', '')

            # TODO: Handle multi-valued certs.
            if pem.strip() != val:
                self.failure(
                    'Certificate %s does not match %s'
                    % (blobs[nickname], paths.CA_CS_CFG_PATH))

    def compare_requests(self):
        """
        Compare cert serial numbers to their request

        The CA subsystem certificates are renewed using the certmonger
        CA dogtag-ipa-ca-renew-agent. This renews by serial number,
        sending CS a request like:
            GET /ca/ee/ca/profileSubmit?profileId=caServerCert&serial_num=5&
                renewal=true&xml=true&requestor_name=IPA

        CS uses the existing cert to generate and return a new one.

        Double-check that the cert in that request entry,
           dn: cn=<serial#>,ou=ca,ou=requests,o=ipaca
        """
        requests = self.get_requests()

        for request in requests:
            if request.get('ca-name') != 'dogtag-ipa-ca-renew-agent':
                continue
            request_id = certmonger.get_request_id(request)
            serial = int(certmonger.get_request_value(request_id, 'serial'),
                         16)
            template_subject = DN(certmonger.get_request_value(
                request_id, 'template-subject'))

            dn = DN(('cn', serial), ('ou', 'ca'), ('ou', 'requests'),
                    ('o', 'ipaca'))

            try:
                entries = self.conn.get_entries(dn,
                                                self.conn.SCOPE_SUBTREE)
            except errors.NotFound:
                self.failure('Unable to find request for serial %s' %
                             serial)
            except Exception as e:
                self.failure('Failed to load request for serial %s' %
                             serial)
            else:
                s = entries[0].get('extdata-req--005fsubject--005fname')
                if s is None:
                    continue
                subject_der = base64.b64decode(s[0])
                subject = DN(der_to_subject(subject_der))
                subject = DN(der_to_subject(subject_der))

                logger.debug('CS template %s, CM subject %s, serial %s',
                             subject, template_subject, serial)

                if ((subject != template_subject) and
                        (subject != template_subject.x500_text())):
                    self.failure('Subject %s and template subject %s '
                                 'do not match for serial %s' %
                                 (subject, template_subject, serial))

    def check_ra_cert(self):
        """Check the RA certificate subject & blob against LDAP"""

        if not self.conn:
            self.failure('Skipping RA check because no LDAP connection')
            return

        cert = x509.load_certificate_from_file(paths.RA_AGENT_PEM)

        serial_number = cert.serial_number
        subject = DN(cert.subject)
        issuer = DN(cert.issuer)
        description = '2;%d;%s;%s' % (serial_number, issuer, subject)

        logger.debug('RA agent description should be %s', description)

        db_filter = ldap2.ldap2.combine_filters(
            [
                ldap2.ldap2.make_filter({'objectClass': 'inetOrgPerson'}),
                ldap2.ldap2.make_filter(
                    {'description': ';%s;%s' % (issuer, subject)},
                    exact=False, trailing_wildcard=False),
            ],
            ldap2.ldap2.MATCH_ALL)

        base_dn = DN(('o', 'ipaca'))
        try:
            entries = self.conn.get_entries(base_dn,
                                            self.conn.SCOPE_SUBTREE,
                                            db_filter)
        except errors.NotFound:
            self.failure('RA agent certificate not found in LDAP')
            return
        except Exception as e:
            self.failure('RA agent check failed %s' % e)
            return
        else:
            if len(entries) != 1:
                self.failure('Too many RA agent entries found')
            entry = entries[0]
            ra_desc = entry.get('description')[0]
            ra_certs = entry.get('usercertificate')
            if ra_desc != description:
                self.failure('RA agent description does not match '
                             '%s in LDAP and %s expected' %
                             (ra_desc, description))
            found = False
            for check in ra_certs:
                if isinstance(check, str):
                    check = load_der_certificate(check)
                if check == cert:
                    found = True
                    break
            if not found:
                self.failure('RA agent certificate not found in LDAP')

    def check_ipa_to_cs_authorities(self):
        """Check that the authorities in IPA are in CS"""
        if not self.conn:
            self.failure(
                'Skipping authorities check because no LDAP connection'
            )
            return

        ca_base_dn = DN(('ou', 'authorities'), ('ou', 'ca'), ('o', 'ipaca'))

        db_filter = ldap2.ldap2.make_filter({'objectClass': 'ipaca'})

        base_dn = DN(api.env.container_ca, api.env.basedn)
        try:
            entries = self.conn.get_entries(base_dn,
                                            self.conn.SCOPE_SUBTREE,
                                            db_filter)
        except errors.NotFound:
            self.failure('CA authorities not found')
            return
        except Exception as e:
            self.failure('Search for authorities failed %s' % e)
            return
        else:
            for entry in entries:
                caid = entry.get('ipacaid')[0]
                logger.debug('Looking for IPA authority %s in CS', caid)
                try:
                    e = self.conn.get_entries(ca_base_dn,
                                              self.conn.SCOPE_SUBTREE,
                                              'cn=%s' % caid)
                except Exception as e:
                    self.failure('Error looking up IPA CA entry in '
                                 'CA %s: %s', caid, e)

    def check_cs_to_ipa_authorities(self):
        """Check that the authorities in CS are in IPA"""
        if not self.conn:
            self.failure(
                'Skipping authorities check because no LDAP connection'
            )
            return

        ca_base_dn = DN(('ou', 'authorities'), ('ou', 'ca'), ('o', 'ipaca'))

        db_filter = ldap2.ldap2.make_filter({'objectClass': 'authority'})

        base_dn = DN(api.env.container_ca, api.env.basedn)
        try:
            entries = self.conn.get_entries(ca_base_dn,
                                            self.conn.SCOPE_SUBTREE,
                                            db_filter)
        except errors.NotFound:
            self.failure('CA authorities not found in CS')
            return
        except Exception as e:
            self.failure('Search for authorities failed %s' % e)
            return
        else:
            for entry in entries:
                caid = entry.get('cn')[0]
                logger.debug('Looking for CS authority %s in IPA', caid)
                try:
                    e = self.conn.get_entries(base_dn,
                                              self.conn.SCOPE_SUBTREE,
                                              'ipacaid=%s' % caid)
                except Exception as e:
                    self.failure('Error looking up CA entry in '
                                 'IPA %s: %s' % (caid, e))

    def check_hostkeytab(self):
        """Ensure the host keytab can get a TGT"""
        ccache_dir = tempfile.mkdtemp()
        ccache_name = os.path.join(ccache_dir, 'ccache')

        try:
            try:
                host_princ = str('host/%s@%s' % (api.env.host, api.env.realm))
                kinit_keytab(host_princ, paths.KRB5_KEYTAB, ccache_name)
            except gssapi.exceptions.GSSError as e:
                self.failure('Failed to obtain host TGT: %s' % e)
        finally:
            installutils.remove_file(ccache_name)
            os.rmdir(ccache_dir)

    def validate_certs(self):
        """Use certutil -V to validate the certs we can"""
        ca_pw_name = None

        if self.ca.is_configured():
            ca_passwd = None
            token = 'internal'
            with open(paths.PKI_TOMCAT_PASSWORD_CONF, 'r') as f:
                for line in f:
                    (tok, pin) = line.split('=', 1)
                    if token == tok:
                        ca_passwd = pin.strip()
                        break
                else:
                    self.failure("The password to the 'internal' "
                                 "token of the Dogtag certificate "
                                 "store was not found.")
            with tempfile.NamedTemporaryFile(mode='w',
                                             delete=False) as ca_pw_file:
                ca_pw_file.write(ca_passwd)
                ca_pw_name = ca_pw_file.name

        try:
            validate = [
                (
                    dsinstance.config_dirname(self.serverid),
                    self.ds.get_server_cert_nickname(self.serverid),
                    os.path.join(dsinstance.config_dirname(self.serverid),
                                 'pwdfile.txt'),

                ),
            ]

            if self.ca.is_configured():
                validate.append(
                    (
                        paths.PKI_TOMCAT_ALIAS_DIR,
                        'Server-Cert cert-pki-ca',
                        ca_pw_name,
                    ),
                )

            if version.NUM_VERSION < 40700:
                validate.append(
                    (
                        paths.HTTPD_ALIAS_DIR,
                        self.http.get_mod_nss_nickname(),
                        os.path.join(paths.HTTPD_ALIAS_DIR, 'pwdfile.txt'),
                    ),
                )

            for (dbdir, nickname, pinfile) in validate:
                args = [paths.CERTUTIL, "-V", "-u", "V", "-e"]
                args.extend(["-d", dbdir])
                args.extend(["-n", nickname])
                args.extend(["-f", pinfile])

                try:
                    result = ipautil.run(args)
                except ipautil.CalledProcessError as e:
                    self.failure('Validation of %s in %s failed: %s'
                                 % (nickname, dbdir, e))
                else:
                    if 'certificate is valid' not in \
                            result.raw_output.decode('utf-8'):
                        self.failure(
                            'Validation of %s in %s failed: '
                            '%s %s' % (nickname, dbdir,
                                       result.raw_output, result.error_log))
        finally:
            if ca_pw_name:
                installutils.remove_file(ca_pw_name)

        if version.NUM_VERSION >= 40700:
            self.validate_openssl(paths.HTTPD_CERT_FILE)

        self.validate_openssl(paths.RA_AGENT_PEM)

    def check_renewal_master(self):
        """Compare is_renewal_master to local config"""
        if not self.conn:
            self.failure(
                'Skipping renewal master check because no LDAP connection'
            )
            return

        dn = DN(('cn', 'masters'), ('cn', 'ipa'),
                ('cn', 'etc'), api.env.basedn)
        renewal_filter = '(&(cn=CA)(ipaConfigString=caRenewalMaster))'

        try:
            entries = self.conn.get_entries(base_dn=dn,
                                            filter=renewal_filter,
                                            attrs_list=['cn'])
        except errors.NotFound:
            self.failure('No certificate renewal master configured')
        except Exception as e:
            self.failure('Failed to get certificate renewal master %s'
                         % e)
        else:
            if len(entries) == 0:
                self.failure('No certificate renewal master configured')
            elif len(entries) == 1:
                logger.debug('This machine is the renewal master')
            elif len(entries) > 1:
                fqdns = []
                for entry in entries:
                    # Cheating because I know the DN ordering
                    fqdns.append(entry.dn[1].value)
                    self.failure('Multiple certificate renewal '
                                 'masters are configured: %s' %
                                 ','.join(fqdns))

    def cert_api_test(self):
        """Use current credentials to try to view a certificate"""
        serialno = 1  # TODO don't hardcode it

        try:
            api.Command.cert_show(serialno)
        except Exception as e:
            self.failure('cert-show of %s failed: %s' % (serialno, e))

    def check_permissions(self):

        # TODO: see if this is something unique about my install
        if version.NUM_VERSION < 40700:
            dirsrv_group = 'root'
        else:
            dirsrv_group = 'dirsrv'

        databases = [
            {
                'dirname': dsinstance.config_dirname(self.serverid),
                'files': [
                    (KEYDB, 'dirsrv', 'root', '0640'),
                    (CERTDB, 'dirsrv', 'root', '0640'),
                    (SECDB, 'dirsrv', dirsrv_group, '0640'),
                ]
            },
            {
                'dirname': paths.VAR_LIB_IPA,
                'files': [
                    ('ra-agent.key', 'root', 'ipaapi', '0440'),
                    ('ra-agent.pem', 'root', 'ipaapi', '0440'),
                ]
            },
        ]

        if self.ca.is_configured():
            databases.append(
                {
                    'dirname': paths.PKI_TOMCAT_ALIAS_DIR,
                    'files': [
                        (KEYDB, 'pkiuser', 'pkiuser', '0600'),
                        (CERTDB, 'pkiuser', 'pkiuser', '0600'),
                        (SECDB, 'pkiuser', 'pkiuser', '0600'),
                    ]
                },
            )

        if version.NUM_VERSION < 40700:
            databases.append(
                {
                    'dirname': paths.HTTPD_ALIAS_DIR,
                    'files': [
                        # file, owner, group, perms
                        (KEYDB, 'root', 'apache', '0640'),
                        (CERTDB, 'root', 'apache', '0640'),
                        (SECDB, 'root', 'apache', '0640'),
                    ]
                },
            )

        for db in databases:
            for (file, owner, group, mode) in db['files']:
                path = os.path.join(db['dirname'], file)
                stat = os.stat(path)
                fmode = str(oct(stat.st_mode)[-4:])
                logger.debug(path)
                if mode != fmode:
                    self.failure('Permissions of %s are %s and should '
                                 'be %s' % (path, fmode, mode))
                fowner = pwd.getpwnam(owner)
                if fowner.pw_uid != stat.st_uid:
                    actual = pwd.getpwuid(stat.st_uid)
                    self.failure('Ownership of %s is %s and should '
                                 'be %s' %
                                 (path, actual.pw_name, owner))
                fgroup = grp.getgrnam(group)
                if fgroup.gr_gid != stat.st_gid:
                    actual = grp.getgrgid(stat.st_gid)
                    self.failure('Group of %s is %s and should '
                                 'be %s' %
                                 (path, actual.gr_name, group))

if __name__ == '__main__':
    args = parser.parse_args()

    api.bootstrap(in_server=True,
                  debug=args.debug,
                  context='cert_check',
                  confdir=paths.ETC_IPA)
    try:
        api.finalize()
    except errors.CCacheError:
        logger.error("admin level Kerberos credentials are required")
        sys.exit(1)

    if args.verbose:
        format = '%(levelname)s: %(message)s'
    else:
        format = '%(message)s'
    ipa_log_manager.standard_logging_setup(
        None,
        verbose=True,
        debug=args.verbose,
        console_format=format
    )

    logger.info('IPA version %s' % version.VENDOR_VERSION)

    if not installutils.is_ipa_configured():
        logger.info("IPA is not configured")
        sys.exit(1)
    c = certcheck()
    sys.exit(c.run())
