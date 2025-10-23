from neo4j import GraphDatabase
import logging

LOG = logging.getLogger('autobloody')

class Database:
    def __init__(self, uri, user, password):
        logging.getLogger("neo4j").setLevel(logging.WARNING)
        self.driver = GraphDatabase.driver(uri, auth=(user, password))
        self._checkGDS()
        self._prepareDb()

    def getPrivescPath(self, source, target):
        with self.driver.session() as session:
            relationships = session.execute_read(
                self._findShortestPath, source, target
            )
        return relationships

    def close(self):
        self.driver.close()
    
    def _checkGDS(self):
        """Check if GDS plugin is installed"""
        with self.driver.session() as session:
            try:
                # Try to call a GDS function
                result = session.run("RETURN gds.version()").single()
                self.gds_available = True
                LOG.info(f"GDS plugin detected (version {result[0]})")
            except Exception:
                self.gds_available = False
                LOG.warning("GDS plugin not detected, will use native CYPHER queries (slower)")

    def _prepareDb(self):
        with self.driver.session() as session:
            session.execute_write(self._setWeight)
            if self.gds_available:
                session.execute_write(self._createGraph)

    # Cost is based on edge exploitation difficulty and impact
    # If ldap doesn't need to be queried like with MemberOf, it has no cost
    # If edge gives Domain Admin rights, it has the lowest cost
    # If edge only requires reading ldap like ReadGMSAPassword, it has a low cost
    # If edge requires writing ldap, the cost will be higher and depend of how much writing is needed (e.g.WriteOwner requires 3 writing)
    # If edges requires manual steps after like GPO edges, cost is higher
    # If edges requires potentially changing passwords, cost is higher because it can disrupt services
    @staticmethod
    def _setWeight(tx):
        # Existing edges on https://github.com/BloodHoundAD/BloodHound/blob/master/docs/data-analysis/edges.rst
        bloodycosts = [
            {"cost": 0, "edges": "MemberOf", "endnode": "Group"},
            {
                "cost": 1,
                "edges": "DCSync|GenericAll|GetChangesAll|AllExtendedRights",
                "endnode": "Domain",
            },
            {"cost": 2, "edges": "WriteDacl|Owns", "endnode": "Domain"},
            {"cost": 3, "edges": "WriteOwner", "endnode": "Domain"},
            {"cost": 10, "edges": "ReadGMSAPassword", "endnode": ""},
            {
                "cost": 100,
                "edges": "AddSelf|AddMember|GenericAll|GenericWrite|AllExtendedRights|Contains",
                "endnode": "Group",
            },
            {"cost": 200, "edges": "WriteDacl|Owns", "endnode": "Group"},
            {"cost": 300, "edges": "WriteOwner", "endnode": "Group"},
            # If we already have GenericAll right on OU we must ensure inheritance or we'll add a new GenericAll ACE with inheritance
            {"cost": 400, "edges": "Contains|GenericWrite|GenericAll", "endnode": "OU"},
            {"cost": 500, "edges": "WriteDacl|Owns", "endnode": "OU"},
            {"cost": 600, "edges": "WriteOwner", "endnode": "OU"},
            {"cost": 10000, "edges": "Contains|GenericWrite|GenericAll", "endnode": "GPO"},
            {"cost": 11000, "edges": "WriteDacl|Owns", "endnode": "GPO"},
            {"cost": 12000, "edges": "WriteOwner", "endnode": "GPO"},
            {
                "cost": 100000,
                "edges": "GenericWrite|GenericAll|AllExtendedRights|Contains",
                "endnode": "User",
            },
            {"cost": 100001, "edges": "WriteDacl|Owns", "endnode": "User"},
            {"cost": 100002, "edges": "WriteOwner", "endnode": "User"},
            {
                "cost": 100000,
                "edges": "GenericWrite|GenericAll|AllExtendedRights|Contains",
                "endnode": "Computer",
            },
            {"cost": 100001, "edges": "WriteDacl|Owns", "endnode": "Computer"},
            {"cost": 100002, "edges": "WriteOwner", "endnode": "Computer"},
            {
                "cost": 110000,
                "edges": "ForceChangePassword",
                "endnode": "",
            },
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

    def _findShortestPath(self, tx, source, target):
        if self.gds_available:
            # Use GDS plugin for better performance
            result = (
                tx.run(
                    "MATCH (s {name:$source}) MATCH (t {name:$target}) CALL"
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
        else:
            # Use native CYPHER for shortest path (slower but doesn't require GDS)
            # This implementation uses built-in shortestPath with cost accumulation
            # Limited to 20 hops max to avoid performance issues
            # Only consider relationships that have bloodycost set (exploitable edges)
            result = tx.run(
                """
                MATCH path = shortestPath((start {name: $source})-[*..20]->(end {name: $target}))
                WHERE ALL(r IN relationships(path) WHERE r.bloodycost IS NOT NULL)
                WITH path, relationships(path) as rels
                WITH path, reduce(cost = 0, r in rels | cost + r.bloodycost) as totalCost
                RETURN path
                ORDER BY totalCost
                LIMIT 1
                """,
                source=source,
                target=target,
            ).single()
            
            if not result:
                raise ValueError("No path exploitable by autobloody found")
            return result[0].relationships
