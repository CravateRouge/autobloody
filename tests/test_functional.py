import unittest, subprocess, pathlib, json, os


class TestModules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        conf = json.loads((pathlib.Path(__file__).parent / "secrets.json").read_text())
        cls.domain = conf["domain"]
        cls.rootDomainNamingContext = ",".join(
            ["DC=" + subdomain for subdomain in cls.domain.split(".")]
        )
        cls.host = conf["pdc"]["ip"]
        cls.admin = {
            "username": conf["admin_user"]["username"],
            "password": conf["admin_user"]["password"],
        }
        cls.pkinit_path = conf["pkinit_path"]
        cls.toTear = []
        cls.env = os.environ.copy()
        cls.autobloody_prefix = [
            "python3",
            "autobloody.py",
            "--host",
            cls.host,
            "-d",
            cls.domain,
        ]
        cls.neo4j = {
            "username": conf["neo4j"]["username"],
            "password": conf["neo4j"]["password"],
            "uri": conf["neo4j"]["uri"],
        }
        # db = Database(cls.neo4j)
        # graph = populateAD()
        # db.createGraph(graph)
        # db.close()

    def test_SimpleRun(self):
        # TODO Add edges/nodes to neo4j database and delete them at the end of the run
        # TODO Add objects to AD and delete them at the end of the run
        # TODO check error if path doesn't exist in DB
        self.launchProcess(
            self.autobloody_prefix
            + [
                "-y",
                "-u",
                "auto.john",
                "-p",
                "Password123!",
                "-dp",
                "Password123!",
                "-ds",
                "AUTO.JOHN@BLOODY.LOCAL",
                "-dt",
                "BLOODY.LOCAL",
            ]
        )

    def populateAD():
        graph = [
            {
                "name": "AddSelf",
                "snode": {
                    "label": "User",
                    "prop": {
                        "name": "auto.selfuser",
                        "distinguishedname": "",
                        "objectId": "",
                    },
                },
                "enode": {
                    "label": "Group",
                    "prop": {
                        "name": "auto.selfgroup",
                        "distinguishedname": "",
                        "objectId": "",
                    },
                },
            }
        ]

        return graph

    def pkinit(self, username, outfile):
        self.assertRegex(
            self.launchProcess(
                [
                    "python3",
                    f"{self.pkinit_path}/gettgtpkinit.py",
                    "-dc-ip",
                    self.host,
                    "-cert-pem",
                    f"{outfile}_cert.pem",
                    "-key-pem",
                    f"{outfile}_priv.pem",
                    f"{self.domain}/{username}",
                    f"{outfile}.ccache",
                ],
                False,
            ),
            "Saved TGT to file",
        )
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
        out, err = subprocess.Popen(
            cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE, env=self.env
        ).communicate()
        out = out.decode()
        if isErr:
            self.assertTrue(out, self.printErr(err.decode(), cmd))
        else:
            out += "\n" + err.decode()
        if doPrint:
            print(out)
        return out

    def printErr(self, err, cmd):
        err = err.replace("\n", "\n ")
        self.err = f"here is the error output ->\n\n {cmd}\n{err}"
        return self.err


from neo4j import GraphDatabase


class Database:
    def __init__(self, neo4j_creds):
        self.driver = GraphDatabase.driver(
            neo4j_creds["uri"], auth=(neo4j_creds["user"], neo4j_creds["password"])
        )
        self._prepareDb()

    def close(self):
        self.driver.close()

    def createGraph(self, graph):
        with self.driver.session() as session:
            session.write_transaction(self._createGraph, graph)

    def destroyGraph(self, graph):
        with self.driver.session() as session:
            session.write_transaction(self._destroyGraph, graph)

    @staticmethod
    def _createGraph(tx, graph):
        for rel in graph:
            tx.run(
                "CREATE (n:$slabel $sprop)",
                slabel=rel["snode"]["label"],
                elabel=rel["enode"]["label"],
            )

    @staticmethod
    def _destroyGraph(tx, graph):
        pass


if __name__ == "__main__":
    unittest.main(failfast=True)
