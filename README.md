Users: Stephen Jacob, Glenn O'Raw

# Neo4j database

Load the neo4j-44.dump file after neo4j service and status is running at http://localhost:7474/browser/

The database of Neo4j objects can be loaded with the following commands 
```
sudo neo4j stop
sudo neo4j-admin database load neo4j --from-path=/source/Folder/neo4j.dump --overwrite-destination=true
sudo neo4j restart 
```

# GraphQL API Server for Neo4j

Enter directory ''graphql-api'' and depending on your choice look at the RUN_**.md files (RUN_LOCALLY is recommended). 

# Run Cytoscape Backend Server to visualize the Interactive Visualization NodeJS application.

1. Enter directory ''vnCytoscapeVisualization''

2. Use node v18.
```
nvm use 18
```

3. Install node packages 
```
npm install .
```

4. Run server
```
node server.js
```

5. The backend application is visible on http://localhost:3000

# Run D3 Backend Server to visualize the Network Landscape NodeJS application.
1. Enter directory ''vnD3Visualization''

2. Use Node v18.
```
nvm use 18
```

3. Install node packages
```
npm install .
```

4. Run server
```
node server.js
```

5. The backend application is visble on http://localhost:3001.
