Users: Stephen Jacob, Glenn O'Raw

# Neo4j database

Load the neo4j-44.dump file after neo4j service and status is running at http://localhost:7474/browser/

The database of Neo4j objects can be loaded by running
```
sudo neo4j-admin load --from source/Folder/neo4j-44.dump --database=neo4j --force
```

# GraphQL API Server for Neo4j

Enter directory ''graphql-api'' folder and depending on your choice look at the RUN_**.md files (RUN_LOCALLY is recommended). 

# Cytoscape Backend Server for Interactive Visualization Panel

Enter directory
