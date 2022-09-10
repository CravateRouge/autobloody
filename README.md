# ![bloodyAD logo](https://repository-images.githubusercontent.com/415977068/9b2fed72-35fb-4faa-a8d3-b120cd3c396f) autobloody
autobloody is a tool to automatically exploit Active Directory privilege escalation paths shown by BloodHound combining `pathgen` and `autobloody`.

## Description
This tool automates the AD privesc between two AD objects, the source (the one we own) and the target (the one we want) if a privesc path exists in BloodHound database.
The automation is split in two parts in order to be used transparently with tunneling tools such as proxychains:
- `pathgen` to find the optimal path for privesc using bloodhound data and neo4j queries.
- `autobloody` to execute the path found with `pathgen`

autobloody relies on [bloodyAD](https://github.com/CravateRouge/bloodyAD) and supports authentication using cleartext passwords, pass-the-hash, pass-the-ticket or certificates and binds to LDAP services of a domain controller to perform AD privesc.

## Installation
A python package is available:
```ps1
pip install autobloody
```

Or you can clone the repo:
```ps1
git clone --depth 1 https://github.com/CravateRouge/autobloody
pip install .
```
### Dependencies
- [bloodyAD](https://github.com/CravateRouge/bloodyAD)
- Neo4j python driver
- Neo4j with the [GDS library](https://neo4j.com/docs/graph-data-science/current/installation/)
- BloodHound
- Python 3

## How to use it
First data must be imported into BloodHound (e.g using SharpHound or BloodHound.py) and Neo4j must be running.

> :warning: **-ds and -dt values are case sensitive**  

Simple usage:
```ps1
pathgen -dp neo4jPass -ds 'OWNED_USER@ATTACK.LOCAL' -dt 'TARGET_USER@ATTACK.LOCAL' && proxychains autobloody.py -d ATTACK -u 'owned_user' -p 'owned_user_pass' --host dc01.attack.local
```

Full help for `pathgen`:
```ps1
[bloodyAD]$ pathgen -h
usage: pathgen [-h] [--dburi DBURI] [-du DBUSER] -dp DBPASSWORD -ds DBSOURCE -dt DBTARGET [-f FILEPATH]

Attack Path Generator

options:
  -h, --help            show this help message and exit
  --dburi DBURI         The host neo4j is running on (default is "bolt://localhost:7687")
  -du DBUSER, --dbuser DBUSER
                        Neo4j username to use (default is "neo4j")
  -dp DBPASSWORD, --dbpassword DBPASSWORD
                        Neo4j password to use
  -ds DBSOURCE, --dbsource DBSOURCE
                        Case sensitive label of the source node (name property in bloodhound)
  -dt DBTARGET, --dbtarget DBTARGET
                        Case sensitive label of the target node (name property in bloodhound)
  -f FILEPATH, --filepath FILEPATH
                        File path for the graph path file (default is "path.json")
```

Full help for `autobloody`:
```ps1
[bloodyAD]$ autobloody -h
usage: autobloody [-h] [-d DOMAIN] [-u USERNAME] [-p PASSWORD] [-k] [-s] --host HOST [--path PATH]

Attack Path Executor

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        Domain used for NTLM authentication
  -u USERNAME, --username USERNAME
                        Username used for NTLM authentication
  -p PASSWORD, --password PASSWORD
                        Cleartext password or LMHASH:NTHASH for NTLM authentication
  -k, --kerberos
  -c CERTIFICATE, --certificate CERTIFICATE
                        Certificate authentication, e.g: "path/to/key:path/to/cert"
  -s, --secure          Try to use LDAP over TLS aka LDAPS (default is LDAP)
  --host HOST           Hostname or IP of the DC (ex: my.dc.local or 172.16.1.3)
  --path PATH           Filename of the attack path generated with pathgen.py (default is "path.json")
```

## How it works
First `pathgen` generates a privesc path using the Dijkstra's algorithm implemented into the Neo4j's GDS library.
The Dijkstra's algorithm allows to solve the shortest path problem on a weighted graph. By default the edges created by BloodHound don't have weight but a type (e.g MemberOf, WriteOwner). A weight is then added to each edge accordingly to the type of edge and the type of node reached (e.g user,group,domain).

Once a path is generated and stored as a json file, `autobloody` will connect to the DC and execute the path and clean what is reversible (everything except password change).

## Limitations
For now, only the following BloodHound edges are currently supported for automatic exploitation:
- MemberOf
- ForceChangePassword
- AddMembers
- AddSelf
- DCSync
- GetChanges/GetChangesAll
- GenericAll
- WriteDacl
- GenericWrite
- WriteOwner
- Owns
- Contains
- AllExtendedRights