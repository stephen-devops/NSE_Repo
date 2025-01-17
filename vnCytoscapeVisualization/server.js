const express = require('express');
const path = require('path');
const neo4j = require('neo4j-driver');
require('dotenv').config();

// define a new virtualNetwork
const graphlib = require('graphlib');
let virtualNetwork = new graphlib.Graph();

const fs = require('fs');

// Neo4j credentials from environment variables
const uri = process.env.NEO4J_SERVER_URL || 'bolt://localhost:7687';
const user = process.env.NEO4J_USERNAME || 'neo4j';
const password = process.env.NEO4J_PASSWORD || 'myNeo4jPassword';
const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));

// Initialize Express.js
const app = express();
const port = 3000; // Port to run the web server

// Serve the static files (HTML, CSS, JS) from the public directory
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.json());

const virtualNetworkFilePath = path.join(__dirname, 'data', 'virtualNetwork.json');

// define a CIDR prefix
const cidrPrefix = '147.251.96.';
const cidrPostfix = '0/24';

//////   Neo4j Queries   //////
// initial data from Neo4j database
async function getInitialCIDRNotation() {
    const session = driver.session();
    // console.log('Initial CIDR Notation:');

    try {

	// define initial Neo4j query
	const query = `MATCH (o:OrganizationUnit) WHERE o.name in ["FF"] WITH o ` +
			`MATCH (o)-[r]-(s:Subnet) WHERE s.range IN ["${cidrPrefix}${cidrPostfix}"] ` +
			`RETURN o, r, s;`;

        // Run a query to fetch nodes (adjust the query as needed)
        const result = await session.run(query);

	const elements = [];

        let nodeId = null;
	let nodeType = 'CIDR_Node';
	let nodeDetails = null;
	let nodeLabel = null;

	// Process the result and convert the responding nodes to Cytoscape elements
	result.records.forEach(record => {

	    record.keys.forEach(key => {

		const node = record.get(key);

		if (node && node.labels) {

		    currentNode = node.labels[0];

		    // handle node and create a CIDR_Node element
		    if (currentNode === 'OrganizationUnit'){

			// console.log('OrgUnit', currentNode);
			nodeId = node.identity.low;
			nodeDetails = node.properties.name;
		    }

		    else if (currentNode === 'Subnet'){

			// console.log('Subnet', node);
			nodeLabel = node.properties.range;
		    }
		}
	    });

	});

        elements.push({
	    data: {
		id: nodeId,
		type: nodeType,
		label: nodeLabel,
		details: nodeDetails
	    }
	});

	// console.log('Initial Neo4j Query Elements: ', elements);
	return elements;
    } catch (error) {
	console.error('Error fetching initial CIDR notation from Neo4j:', error);
	return [];
    } finally {
	await session.close();
    }
}

async function getNeighborNodes(nodeId, nodeType) {
    const session = driver.session();

    try {
        let query = ''; // Change to let to allow reassignment

        if (nodeType === 'CIDR_Node') {
            query = `MATCH (o:OrganizationUnit) WHERE id(o) = $nodeId WITH o ` +
                `MATCH (o)-[r]-(s:Subnet) WHERE s.range CONTAINS $cidrPrefix ` +
                `AND NOT s.range ENDS WITH $cidrPostfix ` +
                `RETURN r, s;`;
        } else if (nodeType === 'Subnet') {
            query = `MATCH (s:Subnet)-[r]-(ip:IP) WHERE id(s) = $nodeId ` +
                `RETURN s, r, ip;`;
        } else if (nodeType === 'IP') {
	    query = `MATCH (i:IP)-[r]-(d:DomainName), (i)-[r1]-(n:Node), (n)-[r2]-(h:Host), ` +
		`(h)-[r3]-(sv:SoftwareVersion) WHERE id(i) = $nodeId WITH r, d, r1, n, r2, h, r3, sv ` +
		`LIMIT 1 ` +
		`OPTIONAL MATCH (sv)-[sR1]-(ns:NetworkService) ` +
		`OPTIONAL MATCH (sv)-[sR2]-(v:Vulnerability) ` +
		`OPTIONAL MATCH (v)-[vulnR]-(c:CVE) ` +
		`RETURN r, d, r1, n, r2, h, r3, sv, sR1, ns, sR2, v, vulnR, c ` +
		`LIMIT 1;`;
	}

        // Ensure the query is not empty
        if (!query) {
            throw new Error('Cypher query is empty');
        }

        // Pass the cidrPrefix and cidrPostfix along with nodeId and nodeType
        const result = await session.run(query, {
            nodeId: parseInt(nodeId),
            nodeType: nodeType,
            cidrPrefix: cidrPrefix,
            cidrPostfix: cidrPostfix
        });

        const elements = [];
        result.records.forEach(record => {
            record.keys.forEach(key => {
                const node = record.get(key);

                // Check if the node is not null
                if (node) {
                    if (!node.type) {
                        const nodeID = node.identity['low'];
                        const nodeType = node.labels[0];
                        const nodeProperty = node.properties;
                        const { nodeLabel, nodeDetails } = getNodeData(nodeType, nodeProperty);

                        elements.push({
                            data: {
                                id: nodeID,
                                type: nodeType,
                                label: nodeLabel,
                                details: nodeDetails
                            }
                        });

                        // Add the node to the virtual network
                        virtualNetwork.setNode(nodeID, { label: nodeLabel, type: nodeType, details: nodeDetails });
                    } else {
                        const edgeSource = node.start['low'];
                        const edgeTarget = node.end['low'];
                        const edgeType = node.type;
                        const edgeID = `${edgeSource}-${edgeTarget}`;

                        elements.push({
                            data: {
                                id: edgeID,
                                source: edgeSource,
                                target: edgeTarget,
                                label: edgeType
                            }
                        });

                        // Add the edge between the source and target to the virtual network
                        virtualNetwork.setEdge(edgeSource, edgeTarget, { id: edgeID, type: edgeType });
                    }
                } else {
                    // console.log(`The node or relationship for key "${key}" is null.`);
		    return;
                }
            });
        });

	// console.log(`getNodeNeighbors of ${nodeId}: `, elements);
        return elements;
    } catch (error) {
        console.error('Error fetching neighbors from Neo4j:', error);
    } finally {
        await session.close();
    }
}

//////   helper functions   //////

// define a function to get the label of a node
function getNodeData(nodeType, nodeProperty){
    //let nodeDetails = '';

    switch (nodeType) {
       case 'Subnet':
           nodeLabel = nodeProperty.range;
	   nodeDetails = nodeProperty.note || 'N/A';
	   break;
       case 'IP':
           nodeLabel = nodeProperty.address || 'N/A';
	   nodeDetails = null
	   break;
       case 'DomainName':
	   nodeLabel = nodeProperty.domain_name || 'N/A';
	   nodeDetails = nodeProperty.tag || 'N/A';
	   break;
       case 'Node':
	   nodeLabel = (nodeProperty.topology_degree || 0).toFixed(1);
	   nodeDetails = (nodeProperty.topology_betweenness || 0).toFixed(1);
	   break;
       case 'Host':
	   nodeLabel = 'Host';
	   nodeDetails = null;
	   break;
       case 'SoftwareVersion':
	   nodeLabel = nodeProperty.version || 'N/A';
	   nodeDetails = nodeProperty.tag || 'N/A';
	   break;
       case 'NetworkService':
           nodeLabel = nodeProperty.protocol || 'N/A';
	   nodeDetails = nodeProperty.service || 'N/A';
	   break;
       case 'Vulnerability':
           nodeLabel = 'Vulnerability';
	   nodeDetails = nodeProperty.description || 'N/A';
	   break;
       case 'CVE':
           nodeLabel = nodeProperty.impact[0] || 'N/A';
	   nodeDetails = (nodeProperty.base_score_v3 || 0).toFixed(1);
	   break;
    }

    return { nodeLabel, nodeDetails };
}

async function collapseVirtualNetwork(expandedData) {

    // console.log('Expanded data to remove: ', expandedData);
    expandedData.forEach(element => {
        const { id, source, target, label, type, parent, details } = element.data;

        if (source !== undefined && target !== undefined) {

            // Remove edge if it exists
            if (virtualNetwork.hasEdge(String(source), String(target))) {
                virtualNetwork.removeEdge(String(source), String(target));
                // console.log(`Removed edge: ${id}`);
            }
        } else if (id !== undefined) {
            // Remove node if it exists
            if (virtualNetwork.hasNode(String(id))) {
                virtualNetwork.removeNode(String(id));
                // console.log(`Removed node: ${id}`);
            }
        }
    });
}

// Consolidate the initial CDIR range fetch the node and save to virtual network
async function fetchAndPopulateCDIR() {
    // const initialCIDR = await getInitialCIDRNotation;
    const initialCIDR = await getInitialCIDRNotation();
    await populateVirtualNetwork(initialCIDR);
    saveVirtualNetwork();
    console.log('Initial data fetched and virtual network populated.');
}

async function populateVirtualNetwork(data) {

    // Check if data is an array
    if (Array.isArray(data)) {
        // Populate the virtualNetwork with the data
        data.forEach(element => {
            const { id, source, target, label, type, parent, details } = element.data;

            // Check if the element is an edge
            if (source !== undefined && target !== undefined) {
                virtualNetwork.setEdge(
                    String(source),
                    String(target),
                    {
                        id: String(id),
                        type: label // This is the relationship type
                    }
                );
            } else if (id !== undefined && type) {
                // Check if element is a node
		const nodeData = { label, type, details };

		// Assign compound parent if available
		if (parent) nodeData.parent = parent;

		virtualNetwork.setNode(String(id), nodeData);
            } else {
		console.error('Element is neither a node nor a valid edge:', element);
		return;
            }
        });

    } else {
        console.error('Data is not an array. Cannot populate virtual network.');
    }
}

async function populateExpandedData(nodeId, nodeType) {
    const expandedData = await getNeighborNodes(nodeId, nodeType);
    // console.log('Expanded Data: ', expandedData);

    // if the expanded node is an IP, define compound node for software and existing vulnerabilities
    if (nodeType === 'IP'){
        const compoundId = `compound-${nodeId}`;
        const vulnerabilityCompoundId = `vulnerability-compound-${nodeId}`;

        // Track presence of specific types
        let hasVulnerabilityData = false;

        // First pass to detect if there is any vulnerability-related data
        expandedData.forEach(element => {
	    const { type } = element.data;
	    if (type === 'Vulnerability' || type === 'NetworkService' || type === 'CVE') {
	        hasVulnerabilityData = true;
	    }
        });

        // Second pass to assign parent attributes based on the presence of vulnerability data
        expandedData.forEach(element => {
	    const { type, id, source } = element.data;

	    // Skip setting a parent for the main node or edges
	    if (id === nodeId || type === 'IP' || source !== undefined) return;

	    // Assign parent based on type and presence of vulnerability data
	    if (hasVulnerabilityData && (type === 'Vulnerability' || type === 'NetworkService'
	    	|| type === 'CVE' || type === 'SoftwareVersion')) {
	        element.data.parent = vulnerabilityCompoundId;
	    } else {
	        // If there's no vulnerability data or node is not vulnerability-related
	        element.data.parent = compoundId;
	    }
        });

        // Add nested vulnerability compound node if vulnerability data exists
        if (hasVulnerabilityData) {
	    expandedData.push({
	        data: {
		    id: vulnerabilityCompoundId,
		    type: 'Compound',
		    label: `Vulnerability Compound for ${nodeId}`,
		    details: null,
		    parent: compoundId
	        }
	    });
        }

        // Add main compound node to expanded data
        expandedData.push({
            data: {
                id: compoundId,
                type: "Compound",
	        details: null,
                label: `Compound Node for ${nodeId}`
            }
        });

    }

    // console.log('\n\nPopulate Network with Expanded Data: ', expandedData);

    await populateVirtualNetwork(expandedData);
}

// function to get virtual network data
async function getVirtualNetworkData() {
    try {
	const elements = [];

        // Add nodes with conditional parent assignment
        virtualNetwork.nodes().forEach(nodeId => {
            const nodeData = {
                id: nodeId,
                label: virtualNetwork.node(nodeId).label,
                type: virtualNetwork.node(nodeId).type,
		details: virtualNetwork.node(nodeId).details
            };

            // Only add 'parent' if it exists for this node
            if (virtualNetwork.node(nodeId).parent) {
                nodeData.parent = virtualNetwork.node(nodeId).parent;
            }

            elements.push({ data: nodeData });
        });

        // Add edges to the elements array
        virtualNetwork.edges().forEach(edge => {
            elements.push({
                data: {
                    id: virtualNetwork.edge(edge).id,
                    source: edge.v,
                    target: edge.w,
                    label: virtualNetwork.edge(edge).type,
                }
            });
        });

	// console.log(`getVirtualNetwork: ${elements}`);
        return elements;
    } catch (error) {
        console.error('Error sending virtual network data:', error);
        res.status(500).json({ error: 'Failed to fetch virtual network data' });
    }
}

// Save the virtual network to a file
function saveVirtualNetwork() {
    try {
        const serializedGraph = graphlib.json.write(virtualNetwork);

        // Ensure the directory exists, create if it doesn't
        if (!fs.existsSync(path.dirname(virtualNetworkFilePath))) {
            fs.mkdirSync(path.dirname(virtualNetworkFilePath), { recursive: true });
        }

        fs.writeFileSync(virtualNetworkFilePath, JSON.stringify(serializedGraph, null, 2));
	console.log('Virtual network saved to:', virtualNetworkFilePath);
    } catch (error) {
        console.error('Error saving virtual network:', error);
    }
}

// Load the virtual network data on server startup
async function loadVirtualNetwork() {
    try {
        if (fs.existsSync(virtualNetworkFilePath,)) {
            const data = fs.readFileSync(virtualNetworkFilePath, 'utf-8');
            if (data) {
                virtualNetwork = graphlib.json.read(JSON.parse(data));
            } else {
                await fetchAndPopulateCDIR();
            }
        } else {
            await fetchAndPopulateCDIR();
        }
    } catch (error) {
        console.error('Error loading virtual network:', error);
    }
}

//////   API calls   //////
// Export the function for use in the API route
module.exports = {
    getInitialCIDRNotation,
    getNeighborNodes,
    getVirtualNetworkData
};

app.get('/api/fetch-cdir-data', async (req, res) => {
    try {
        await fetchAndPopulateCDIR();
        res.json({ message: 'Initial CDIR range fetched and virtual network saved.' });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch initial data.' });
    }
});

// extract data from virtual network
app.get('/api/virtualNetwork', async (req, res) => {
    const data = await getVirtualNetworkData();
    res.json(data);
});

// API route to expand a node and get its neighbors dynamically
app.get('/api/expand/:nodeId/:nodeType', async (req, res) => {
    try {
	const nodeId = req.params.nodeId;
	const nodeType = req.params.nodeType;
        await populateExpandedData(nodeId, nodeType);
	await saveVirtualNetwork();
	res.json({ message: `Neighbor data for ${nodeId} fetched and virtual network saved.` });
    } catch (error) {
	res.status(500).json({ error: 'Failed to fetch neighbor data.' });
    }
});

app.post('/api/collapse', async (req, res) => {
    try {
	const data = req.body;
	await collapseVirtualNetwork(data);
	await saveVirtualNetwork();
    } catch (error) {
	console.error('Error collapsing virtual network:', error);
	res.status(500).json({ error: 'Failed to fetch neighbor data.' });
    }
});

// Start the server and listen on the specified port
app.listen(port, () => {
    console.log(`App listening at http://localhost:${port}`);

    (async () => {
        await loadVirtualNetwork();
    })().catch((error) => {
        console.error('Error loading the virtual network:', error);
    });
});

// Close the Neo4j driver when the process exits
process.on('exit', () => {
    console.log('Exited');
    driver.close();
});

// Delete the virtual network file and reset virtualNetwork on shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down server...');

    // Remove the JSON file if it exists
    if (fs.existsSync(virtualNetworkFilePath)) {
        try {
            fs.unlinkSync(virtualNetworkFilePath);
            console.log('virtualNetwork.json deleted successfully from directory.');
        } catch (error) {
            console.error('Error deleting virtualNetwork.json:', error);
        }
    }

    // Clear the virtual network data
    virtualNetwork = new graphlib.Graph(); // Re-initialize to empty

    // Exit process
    process.exit();
});
