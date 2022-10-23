import unittest, subprocess, pathlib, json, hashlib, os, re


class TestModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf = json.loads((pathlib.Path(__file__).parent / "secrets.json").read_text())
        cls.domain = conf['domain']
        cls.rootDomainNamingContext = ','.join([ "DC="+subdomain for subdomain in cls.domain.split('.') ])
        cls.host = conf['pdc']['ip']
        cls.admin = {
            'username' : conf['admin_user']['username'],
            'password' : conf['admin_user']['password']
        }
        cls.pkinit_path = conf['pkinit_path']
        cls.toTear = []
        cls.env = os.environ.copy()
        cls.autobloody_prefix = ["python3", "autobloody.py", "--host", cls.host, "-d", cls.domain]


    def test_SimpleRun(self):
        # TODO Add edges/nodes to neo4j database and delete them at the end of the run
        # TODO Add objects to AD and delete them at the end of the run
        # TODO check error if path doesn't exist in DB
        self.launchProcess(self.autobloody_prefix+["-y", "-u", "auto.john", "-p", "Password123!", "-dp", "Password123!", "-ds", "AUTO.JOHN@BLOODY.LOCAL", "-dt", "BLOODY.LOCAL"])
        

    def pkinit(self, username, outfile):
        self.assertRegex(self.launchProcess(["python3", f"{self.pkinit_path}/gettgtpkinit.py","-dc-ip", self.host, "-cert-pem", f"{outfile}_cert.pem", "-key-pem", f"{outfile}_priv.pem", f"{self.domain}/{username}", f"{outfile}.ccache"], False), "Saved TGT to file")
        for name in [f"{outfile}_cert.pem", f"{outfile}_priv.pem", f"{outfile}.ccache"]:
            self.toTear.append([(pathlib.Path() / name).unlink])


    @classmethod
    def tearDownClass(cls):
        while len(cls.toTear):
            func = cls.toTear.pop()
            if len(func) > 1:
                func[0](*func[1:])
            else:
                func[0]()


    def launchProcess(self, cmd, isErr=True, doPrint=True):
        out, err = subprocess.Popen(cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=self.env).communicate()
        out = out.decode()
        if isErr:      
            self.assertTrue(out, self.printErr(err.decode(), cmd))
        else:
            out += '\n'+err.decode()
        if doPrint:
            print(out)
        return out
    

    def printErr(self, err, cmd):
        err = err.replace('\n', '\n ')
        self.err = f"here is the error output ->\n\n {cmd}\n{err}"
        return self.err


if __name__ == '__main__':
    unittest.main(failfast=True)