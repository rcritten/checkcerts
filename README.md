# IPA cert checker

Check the CA and general certificate configuration of an IPA master
and report any failures it finds.

This is expected to be merged into another tool eventually so the
"framework" of the command is rather hacky. It basically runs a bunch 
of tests and collects the failures into an array to be displayed
when the tool exits.

It returns 1 if there are any failures found and 0 if it detects things
are ok.

These tests are all read-only and no attempt is made to correct issues
found.

Limited testing has been done but on a single-master install it
should work for IPA 4.5, 4.6 and master (so probably 4.7 as well).

# Usage for 4.5 and 4.6:

It must be run as root and you need Kerberos credentials for an admin user.

```
python2 ipa-checkcerts.py
```

For 4.7 and master:

```
python3 ipa-checkcerts.py
```

# What it checks

## Check CA status

Simple check to see if the CA is up and responding.

## Check tracking

Compares what the tracking for the CA, HTTP, DS and KDC certificates
should look like to what is actually being tracked.

## Check NSS trust

Look at the NSS trust flags on the CA flags to ensure they are what are
expected. (external CA certs are not evaluated yet).

## Check dates

Checks the CA, HTTP and CS certs to determine if the are expired,
expiring soon (7 days) or not valid yet.

## Checking certificates in CS.cfg

Compares the CA certficates in the NSS database to the blob stored in the
userCertificate attribute in LDAP.

## Checking RA certificate

Compares the RA agent blob to the userCertificate value stored in LDAP
and the description attribute, both of which are used during
authentication.

## Checking authorities

Ensures that the CA authorities (IPA and its sub CAs) match between
the IPA LDAP database and the CA LDAP database.

## Checking host keytab

The host keytab is used by certmonger to authenticate to IPA in some
cases so verify that a TGT can be obtained using it.

## Validating certificates

Validate the CA, DS and HTTP (when in NSS) server certificates using
certutil -V -u V.

## Checking renewal master

Ensures that exactly one renewal master is configured.

## End-to-end cert API test

The equivalent of: ipa cert-show 1

This tests that IPA can talk to the CA using the RA agent cert.

## Checking permissions and ownership

Check the filesystem permissions and ownership for the CA, DS and
HTTP (if appropriate by version) databases. Also check the RA agent
certificate PEM file(s).
