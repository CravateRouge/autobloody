from neo4j import GraphDatabase
import logging


class Database:
    def __init__(self, uri, user, password):
        logging.getLogger("neo4j").setLevel(logging.WARNING)
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._prepareDb()

    def getPrivescPath(self, source, target):
        with self.driver.session() as session:
            relationships = session.read_transaction(
                self._findShortestPath, source, target
            )
        return relationships

    def close(self):
        self.driver.close()

    def _prepareDb(self):
        with self.driver.session() as session:
            session.write_transaction(self._setWeight)
            session.write_transaction(self._createGraph)

    @staticmethod
    def _setWeight(tx):
        # Existing edges on https://github.com/BloodHoundAD/BloodHound/blob/master/docs/data-analysis/edges.rst
        bloodycosts = [
            {"cost": 0, "edges": "MemberOf", "endnode": "Group"},
            {
                "cost": 100,
                "edges": "AddSelf|AddMember|GenericAll|GenericWrite|AllExtendedRights|Contains",
                "endnode": "Group",
            },
            {"cost": 200, "edges": "WriteDacl|Owns", "endnode": "Group"},
            {"cost": 300, "edges": "WriteOwner", "endnode": "Group"},
            {
                "cost": 1,
                "edges": "DCSync|GenericAll|GetChangesAll|AllExtendedRights",
                "endnode": "Domain",
            },
            {"cost": 2, "edges": "WriteDacl|Owns", "endnode": "Domain"},
            {"cost": 3, "edges": "WriteOwner", "endnode": "Domain"},
            {
                "cost": 100000,
                "edges": "GenericWrite|GenericAll|AllExtendedRights|Contains",
                "endnode": "User|Computer",
            },
            {"cost": 100001, "edges": "WriteDacl|Owns", "endnode": "User|Computer"},
            {"cost": 100002, "edges": "WriteOwner", "endnode": "User|Computer"},
            {
                "cost": 110000,
                "edges": "ForceChangePassword",
                "endnode": "User|Computer",
            }
            # If we already have GenericAll right on OU we must ensure inheritance so we'll add a new GenericAll ACE with inheritance
            {"cost": 200, "edges": "Contains|GenericWrite|GenericAll", "endnode": "OU|GPO"},
            {"cost": 250, "edges": "WriteDacl|Owns", "endnode": "OU|GPO"},
            {"cost": 350, "edges": "WriteOwner", "endnode": "OU|GPO"},
            {"cost": 10, "edges": "ReadGMSAPassword", "endnode": ""},
        ]
        for bloodycost in bloodycosts:
            endnode = ":" + bloodycost['endnode'] if bloodycost['endnode'] else ""
            tx.run(
                f"MATCH ()-[r:{bloodycost['edges']}]->({endnode}) SET"
                f" r.bloodycost = {bloodycost['cost']}"
            )

    @staticmethod
    def _createGraph(tx):
        graph_exists = tx.run("RETURN gds.graph.exists('autobloody')").single()[0]
        if graph_exists:
            tx.run("CALL gds.graph.drop('autobloody')")
        tx.run(
            "CALL gds.graph.project('autobloody','*',{all:{type:'*',"
            " properties:{bloodycost:{defaultValue:9999999999}}}},{validateRelationships:true})"
        )

    # Alternative with only CYPHER https://liberation-data.com/saxeburg-series/2018/11/28/rock-n-roll-traffic-routing.html
    # CONS: Less efficient, more complex PROS: Doesn't need GDS plugin
    @staticmethod
    def _findShortestPath(tx, source, target):
        result = (
            tx.run(
                "MATCH (s {name:$source}), (t {name:$target}) CALL"
                " gds.shortestPath.dijkstra.stream('autobloody',{sourceNode:s,"
                " targetNode:t, relationshipWeightProperty:'bloodycost'})YIELD path"
                " RETURN path",
                source=source,
                target=target,
            )
        ).single()
        if not result:
            raise ValueError("No path exploitable by autobloody found")
        return result[0].relationships
