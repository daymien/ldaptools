import ldap
import sys
import logging
import pprint
import argparse

logging.basicConfig()
log = logging.getLogger(__name__)

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("uri", help="ldap URL")
    parser.add_argument("user", help="user cn")
    parser.add_argument("-p", "--password", help="user password")
    
    args = parser.parse_args()

    ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_ALLOW)
    l = ldap.initialize(args.uri)
    l.simple_bind_s(args.user, args.password)

    r = l.search_s("ou=contacts,dc=example,dc=org", ldap.SCOPE_SUBTREE)
    for dn, attrs in r:
            cn, dc = dn.split(",", 1)[0], dn.split(",", 1)[1]
            if not cn.endswith(r"\20"):
                continue
            rdn = cn.replace(r"\20", "")
            print("'%s' -> '%s'" %(dn, rdn))
            l.rename_s(dn, rdn)


if __name__ == "__main__":
    sys.exit(main())