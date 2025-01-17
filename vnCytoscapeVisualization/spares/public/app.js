let displayedNodeIDs = {};
let neighborSets = {};
let expandedNodes = new Set();

document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Check if the virtual network data is ready
        const response = await fetch('/api/virtualNetwork');
        const elements = await response.json();

        // If the response is empty, trigger the initial data fetch
        if (!elements || elements.length === 0) {
	    console.log('Fetching cdir data');
            await fetch('/api/fetch-cdir-data');

            // Retry fetching the virtual network data after initial fetch
	    // console.log('Get Virtual network data');
            const newResponse = await fetch('/api/virtualNetwork');
            const newElements = await newResponse.json();
            initializeCytoscape(newElements);
        } else {
            initializeCytoscape(elements);
        }
    } catch (error) {
        console.error('Error loading the virtual network data:', error);
    }

});

function initializeCytoscape(elements) {

    // Initialize Cytoscape with the fetched data
    const cy = cytoscape({
        container: document.getElementById('cy'), // container to render in
        elements: elements,
        style: [
            {
                selector: 'node[type="CIDR_Node"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'black',
                    'shape': 'ellipse',
                    'width': 120,
                    'height': 120,
                    'text-valign': 'center',
                    'color': '#fff',
                    'font-size': '15px'
                }
            },
            {
                selector: 'node[type="Subnet"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'skyblue',
                    'shape': 'ellipse',
                    'width': 120,
                    'height': 120,
                    'text-valign': 'center',
                    'color': 'black',
                    'font-size': '15px'
                }
            },
	    {
                selector: 'node[type="IP"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'yellow',
                    'shape': 'ellipse',
                    'width': 100,
                    'height': 100,
                    'text-valign': 'center',
                    'color': 'black',
                    'font-size': '12px'
                }
            },
            {
                selector: 'edge',
                style: {
                    'width': 1,
                    'line-color': '#ccc',
                    'target-arrow-color': 'black',
                    'target-arrow-shape': 'triangle',
                    'label': 'data(label)',
		    'curve-style': 'bezier',
		    'arrow-scale': 1.5,
                    'font-size': '14px',
                    'text-rotation': 'autorotate',
                    'color': 'blue'
                }
            }
        ],
        layout: {
            name: 'breadthfirst',
	    directed: true,
	    padding: 50,
            rows: 1
        },
        minZoom: 0.5,
        maxZoom: 2.0,
        zoomingEnabled: true
    });

    // console.log('Initializing Elements: ', elements);
    cy.add(elements);

    // Iterate over the elements to collect node IDs
    cy.elements().jsons().forEach(element => {
        if (element.data.id) {
            // Add each node ID to displayedNodeIDs, setting it to true to indicate it's displayed
            displayedNodeIDs[element.data.id] = true;
        }
    });

    // Apply a layout after adding elements to properly position them
    cy.layout({ name: 'breadthfirst', directed: true, padding: 50 }).run();

    // click on an existing Node to show neighbors
    cy.on('dbltap', 'node', async (event) => {

	const node = event.target;
        const nodeId = event.target.id();
	const nodeType = node.data('type');

	// if selected nodeId is absent expand the graph else collapse the graph
	if (expandedNodes.has(nodeId)) {
	    console.log(`Collapsing neighbors of ${nodeId}`);
	    collapseNodesAndRecursiveNodes(nodeId);
	} else {
	    console.log(`Expanding neighbors of ${nodeId}`);
	    expandNodes(nodeId, nodeType);
	}
    });

    async function expandNodes(nodeId, nodeType) {
	try {

	    // Fetch expanded neighbors from the server
	    await fetch(`/api/expand/${nodeId}/${nodeType}`);

	    const expandedResponse = await fetch('/api/virtualNetwork');

	    if (!expandedResponse.ok) throw new Error('Network response was not ok');
	    const expandedData = await expandedResponse.json();

	    // Filter out nodes and edges that are already displayed
	    const filteredExpandedData = expandedData.filter(el => el.data && !displayedNodeIDs[el.data.id]);

	    // Separate first-hop neighbors
	    const neighbors = filteredExpandedData.filter(el => el.data && el.data.id !== nodeId && el.group !== 'edges');

	    // Filter edges connecting nodeA to its first-hop neighbors
	    const filteredEdges = filteredExpandedData.filter(el => {
		if (el.group === 'edges' && el.data) {
		    const { source, target } = el.data;
		    return (source === nodeId && neighbors.some(n => n.data.id === target)) ||
                       (neighbors.some(n => n.data.id === source) && neighbors.some(n => n.data.id === target));
		}
		return false;
	    });

	    // Add filtered data to the Cytopscape
	    cy.add(neighbors);
	    cy.add(filteredEdges);

	    // Track expanded nodes and children
	    expandedNodes.add(nodeId);
	    neighborSets[nodeId] = new Set(neighbors);

	    // design Cytoscape layout
	    const layoutOptions = {
		name: 'breadthfirst',
		directed: true,
		padding: 10,
		fit: true,
		spacingFactor: 1.5,
		animate: true,
		roots: `[id = "${nodeId}"]`
	    };

	    // Apply Cytoscape layout
	    const layout = cy.layout(layoutOptions);

	    layout.stop();
	    layout.run();

	    // Update displayed node IDs
	    cy.elements().jsons().forEach(element => {
		if (element.data.id) {
		    displayedNodeIDs[element.data.id] = true;
		}
	    });

	} catch (error) {
	    console.error('Error expanding node:', error);
	}
    }

    function collapseNodes(nodeId) {
	console.log(`\n\nRemoving neighbors of node: ${nodeId}`);

	// Check if neighbors exist for this node and the node was expanded
	if (!neighborSets[nodeId] || !expandedNodes.has(nodeId)) return;

	const neighbors = Array.from(neighborSets[nodeId]);
	// console.log('\nNeighbor Set: ', neighborSets[nodeId]);
	console.log('Removing Array of Nighbors: ', neighbors);

	// iterate through the array of elements
	for (let i = neighbors.length - 1; i >= 0; i--) {

	    //const neighborId = neighbors[i];
	    const neighbor = neighbors[i];
	    const neighborId = neighbor.data.id;
	    console.log('\nNeighborId to remove: ', neighborId);

	    // Remove the neighbor node and any connected edges
	    const neighborNode = cy.getElementById(neighborId);
	    // const connectedEdges = neighborNode.connectedEdges();
	    console.log('Neighbor to remove: ', neighborNode)

	    cy.batch(() => {
		neighborNode.remove();
	    });
	}

	const updateResponse = fetch(`/api/collapse`, {
    	    method: 'POST',
    	    headers: { 'Content-Type': 'application/json' },
    	    body: JSON.stringify(neighbors)
	});

        // Clean up tracking of expanded nodes
    	neighbors.forEach(neighbor => {

	    neighborId = neighbor.data.id;
            delete displayedNodeIDs[neighborId];
    	});

        delete neighborSets[nodeId];
        expandedNodes.delete(nodeId);

        // Apply layout to the remaining nodes
        const layoutOptions = {
            name: 'breadthfirst',
            directed: true,
            padding: 10,
            fit: true,
            spacingFactor: 1.5,
            animate: true,
            roots: `[id = "${nodeId}"]`
        };

        cy.layout(layoutOptions).run();
    }

    function collapseNodesAndRecursiveNodes(nodeId) {
	console.log(`\nRemoving neighbors of node: ${nodeId}`);
	console.log('Expanded Nodes: ', expandedNodes);

	// collapse a node and its neighbors recursively
	function recursiveCollapse(id) {

	    // Check if neighbors exist for this node and the node was expanded
	    if (!neighborSets[id] || !expandedNodes.has(id)) return;

	    // Get the neighbors
	    const neighbors = Array.from(neighborSets[id]);
	    console.log(`\n\nRecursive collapsing for ${id}, neighbors:`, neighbors);

	    for (let i = neighbors.length - 1; i >= 0; i--) {

		const neighbor = neighbors[i];
		// Remove the neighbor node from Cytoscape
		neighborId = neighbor.data.id;
		console.log('Neighbor to remove: ', neighborId);

		// if neighborId was expanded independently, then collapse recursively
		if (expandedNodes.has(neighborId)) {
		    recursiveCollapse(neighborId);
		    console.log(`Recursively collapsed neighbors for ${neighborId}\n\n`);
		}

		console.log('After recursive function - Neighbor to remove: ', neighborId);
		const neighborNode = cy.getElementById(neighborId);
		console.log(`After recursive function - Remove from Cytoscape: ${neighborNode}\n`);

		cy.batch(() => {
		   neighborNode.remove();
		});
	    }

	    // update the vitual network on the moddle layer
	    const updateResponse = fetch(`/api/collapse`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(neighbors)
	    });

	    // Clean up tracking of expanded nodes
    	    neighbors.forEach(neighbor => {
		neighborId = neighbor.data.id;
		delete displayedNodeIDs[neighborId];
    	    });

	    delete neighborSets[nodeId];
	    expandedNodes.delete(nodeId);

            // Apply layout to the remaining nodes
            const layoutOptions = {
                name: 'breadthfirst',
                directed: true,
                padding: 10,
                fit: true,
                spacingFactor: 1.5,
                animate: true,
                roots: `[id = "${nodeId}"]`
            };

	    const layout = cy.layout(layoutOptions);
	    layout.stop();
            layout.run();
	    console.log(`Collapsed neighbors of ${nodeId}`);
	}

	// Perform a normal collapse
	const lastExpandedNodeId = Array.from(expandedNodes).pop();

	// Only collapse recursively if nodeId is not the last expanded one
	if (nodeId !== lastExpandedNodeId) {

	    console.log(`\n${nodeId} is not the last expanded node. Collapse recursively.\n\n`);
	    recursiveCollapse(nodeId);
	} else {

	console.log('Collapsing the final expanded Node');

	// Collapse only the provided nodeId without recursion
	// const node = cy.getElementById(nodeId);
	const neighbors = Array.from(neighborSets[nodeId] || []);

	console.log('\nCollapsing Neighbors of last expanded node: ', neighbors);

	// iterate through the array
	for (let i = neighbors.length - 1; i >= 0; i--) {

	    const neighbor = neighbors[i];
	    const neighborId = neighbor.data.id;
	    console.log('\nNeighborId of last expanded node to remove: ', neighborId);

	    // Remove the neighbor node
	    const neighborNode = cy.getElementById(neighborId);
	    console.log('Neighbor to remove: ', neighborNode);

	    cy.batch(() => {
		neighborNode.remove();
	    });
	}

	// cy.batch(() => {

	    // neighbors.forEach(neighborId => {

	        //console.log(`\nCollapsing ${neighborId}`);
		//const neighborNode = cy.getElementById(neighborId);
		//console.log(`\nRemoving ${neighborNode}`);

		//neighborNode.remove();
	    //});
	//});


	//neighbors.forEach(neighborId => {

	  //  const neighborNode = cy.getElementById(neighborId);
	  //  console.log(`\nCollapsing ${neighborId}`);
	  //  console.log(`\nCollapsing Data: ${neighborNode.data.id}`);
	  //  console.log(`\nCollapsing ${neighborNode}`);

	  //  cy.batch(() => {
	//	neighborNode.remove();
	  //  });
	//});

	const updateResponse = fetch(`/api/collapse`, {
	    method: 'POST',
	    headers: { 'Content-Type': 'application/json' },
	    body: JSON.stringify(neighbors)
	});

	// Clean up the neighborSets and expandedNodes
	delete neighborSets[nodeId];
	expandedNodes.delete(nodeId);

        // Apply layout to the remaining nodes
        const layoutOptions = {
	    name: 'breadthfirst',
	    directed: true,
	    padding: 10,
	    fit: true,
	    spacingFactor: 1.5,
	    animate: true,
	    roots: `[id = "${nodeId}"]`
	};

	const layout = cy.layout(layoutOptions);
	layout.stop();
	layout.run();
	console.log(`Collapsed neighbors of ${nodeId}`);
	}
    }
}
