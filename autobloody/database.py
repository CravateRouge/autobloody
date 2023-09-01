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
                "edges": "GenericWrite|GenericAll|ForceChangePassword|AllExtendedRights|Contains",
                "endnode": "User",
            },
            {"cost": 100001, "edges": "WriteDacl|Owns", "endnode": "User"},
            {"cost": 100002, "edges": "WriteOwner", "endnode": "User"},
            {
                "cost": 100100,
                "edges": "GenericWrite|GenericAll|ForceChangePassword|AllExtendedRights|Contains",
                "endnode": "Computer",
            },
            {"cost": 100101, "edges": "WriteDacl|Owns", "endnode": "Computer"},
            {"cost": 100102, "edges": "WriteOwner", "endnode": "Computer"},
            # If we already have GenericAll right on OU we must ensure inheritance so we'll add a new GenericAll ACE with inheritance
            {"cost": 0, "edges": "Contains|GenericWrite|GenericAll", "endnode": "OU"},
            {"cost": 250, "edges": "WriteDacl|Owns", "endnode": "OU"},
            {"cost": 350, "edges": "WriteOwner", "endnode": "OU"},
            {"cost": 0, "edges": "GenericWrite|GenericAll|Contains", "endnode": "GPO"},
            {"cost": 250, "edges": "WriteDacl|Owns", "endnode": "GPO"},
            {"cost": 350, "edges": "WriteOwner", "endnode": "GPO"},
        ]
        for bloodycost in bloodycosts:
            tx.run(
                f"MATCH ()-[r:{bloodycost['edges']}]->(:{bloodycost['endnode']}) SET"
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
        result = tx.run(
            "MATCH (s {name:$source}), (t {name:$target}) CALL"
            " gds.shortestPath.dijkstra.stream('autobloody',{sourceNode:s,"
            " targetNode:t, relationshipWeightProperty:'bloodycost'})YIELD path"
            " RETURN path",
            source=source,
            target=target,
        )
        return result.single()[0].relationships
