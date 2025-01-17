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
                selector: 'node[type="Node"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'black',
                    'shape': 'ellipse',
                    'width': 80,
                    'height': 80,
                    'text-valign': 'center',
                    'color': '#fff',
                    'font-size': '15px'
                }
            },
            {
                selector: 'node[type="DomainName"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'blue',
                    'shape': 'rectangle',
                    'width': 100,
                    'height': 60,
                    'text-valign': 'center',
                    'color': '#fff',
                    'font-size': '12px'
                }
            },
	    {
                selector: 'node[type="Host"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'lightgrey',
                    'shape': 'ellipse',
                    'width': 100,
                    'height': 60,
                    'text-valign': 'center',
                    'color': 'black',
                    'font-size': '12px'
                }
            },
            {
                selector: 'node[type="SoftwareVersion"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'aqua',
                    'shape': 'ellipse',
                    'width': 100,
                    'height': 80,
                    'text-valign': 'center',
                    'color': 'black',
                    'font-size': '12px'
                }
            },
            {
                selector: 'node[type="Vulnerability"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'red',
                    'shape': 'square',
                    'width': 80,
                    'height': 80,
                    'text-valign': 'center',
                    'color': 'black',
                    'font-size': '12px'
                }
            },
            {
                selector: 'node[type="CVE"]',
                style: {
                    'label': 'data(label)',
                    'background-color': 'orange',
                    'shape': 'square',
                    'width': 160,
                    'height': 50,
                    'text-valign': 'center',
                    'color': 'black',
                    'font-size': '12px'
                }
            },
	    {
		selector: 'node[id^="compound-"]',
		style: {
		    'background-color': 'skyblue',
		    'background-opacity': 0.333
		}
	    },
	    {
		selector: 'node[id^="vulnerability-compound-"]',
		style: {
		    'background-color': '#ad1a66',
		    'background-opacity': 0.1667
		}
	    },
            {
                selector: 'edge',
                style: {
                    'width': 1,
                    'line-color': 'black',
                    'target-arrow-color': 'black',
                    'target-arrow-shape': 'triangle',
                    'label': 'data(label)',
		    'opacity': '0.55',
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

    console.log('Adding Initial Elements to Cytoscape: ', elements);
    cy.add(elements);

    // Iterate over the elements to collect node IDs
    cy.elements().jsons().forEach(element => {

	console.log(element);

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

	// check if node was in initial Neo4j query
	if (!displayedNodeIDs[nodeId]) {
	    console.log(`Node ${nodeId} was not part of the initial data`);
	    return;
	}

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
        console.log('Expanding neighbors');

        // declare variables for compound nodes and a risk factor
	let compoundNodeId = null;
        let vulnerabilityCompoundNodeId = null;
        let riskFactor = '';

        // Fetch expanded neighbors from the server
        await fetch(`/api/expand/${nodeId}/${nodeType}`);
        const expandedResponse = await fetch('/api/virtualNetwork');
        if (!expandedResponse.ok) throw new Error('Network response was not ok');

        const expandedData = await expandedResponse.json();

	console.log('Expanded Data: ', expandedData);

        // Filter out nodes and edges that are already displayed
        const filteredExpandedData = expandedData.filter(el => el.data && !displayedNodeIDs[el.data.id]);

	console.log('Filtered Expanded Data: ', filteredExpandedData);

        // Separate first-hop neighbors
        const neighbors = filteredExpandedData.filter(el => el.data && el.data.id !== nodeId && el.group !== 'edges');

	console.log('Neighbors Data: ', neighbors);

        // Filter edges connecting nodeA to its first-hop neighbors
        const filteredEdges = filteredExpandedData.filter(el => {
            if (el.group === 'edges' && el.data) {
                const { source, target } = el.data;
                return (source === nodeId && neighbors.some(n => n.data.id === target)) ||
                       (neighbors.some(n => n.data.id === source) && neighbors.some(n => n.data.id === target));
            }
            return false;
        });

        console.log('Neighbors: ', neighbors);
        // console.log('FilteredEdges: ', filteredEdges);

        if (nodeType === 'IP') {
            // Assign the primary compound node for the first-hop neighbors of nodeA
            compoundNodeId = `compound-${nodeId}`;
            cy.add({
                group: 'nodes',
                data: {
                    id: compoundNodeId,
                    label: `Neighbors of ${nodeId}`
                }
            });

            // Check if Vulnerability and CVE nodes are present
            const hasVulnerability = neighbors.some(neighbor => neighbor.data.type === 'Vulnerability');
            const hasCVE = neighbors.some(neighbor => neighbor.data.type === 'CVE');

            if (hasVulnerability && hasCVE) {
                vulnerabilityCompoundNodeId = `vulnerability-compound-${nodeId}`;
                cy.add({
                    group: 'nodes',
                    data: {
                        id: vulnerabilityCompoundNodeId,
                        label: `Vulnerability Compound for ${nodeId}`,
                        parent: compoundNodeId
                    }
                });

                // Set the risk factor if there is a CVE object
                const cveNode = neighbors.find(el => el.data && el.data.type === 'CVE');
                if (cveNode) {
                    riskFactor = cveNode.data.details;
                }
            }

            // Assign parents to neighbors based on the existence of a vulnerability compound
            neighbors.forEach(neighbor => {
                const { type } = neighbor.data;
                if ((type === 'Vulnerability' || type === 'CVE' || type === 'NetworkService' || type === 'SoftwareVersion') && vulnerabilityCompoundNodeId) {
                    neighbor.data.parent = vulnerabilityCompoundNodeId;
                } else {
                    neighbor.data.parent = compoundNodeId;
                }
            });

            // Set a risk factor if assigned
            if (riskFactor !== '') {
                const myNode = expandedData.find(el => el.data && el.data.id === nodeId);
                if (myNode) {
                    const severityLevel = calculateCVSSSeverity(parseFloat(riskFactor) || 0.0);
                    const cyNode = cy.getElementById(nodeId);
                    if (cyNode) {
                        cyNode.data('value', severityLevel);
			console.log('Updated Risk Factor Node:', cyNode.data());
                    } else {
                        console.warn(`Node with ID ${nodeId} not found in Cytoscape.`);
                    }
                }
            }

            // Add nodeA back to the graph if it was removed
            if (!cy.getElementById(nodeId).length) {
                const nodeA = expandedData.find(el => el.data && el.data.id === nodeId);
                if (nodeA) cy.add(nodeA);
            }
        }

        // Add filtered data to Cytoscape
        cy.add(neighbors);
        cy.add(filteredEdges);

        // Track expanded nodes and children
        expandedNodes.add(nodeId);
        neighborSets[nodeId] = new Set(neighbors);

        // Apply layout if compound nodes exist
        const vulnerabilityCompoundNode = vulnerabilityCompoundNodeId ? cy.getElementById(vulnerabilityCompoundNodeId) : null;
        const mainCompoundNode = compoundNodeId ? cy.getElementById(compoundNodeId) : null;

        // Apply layout to the vulnerability compound node's children first, if it exists
        if (vulnerabilityCompoundNode && vulnerabilityCompoundNode.children().length) {

	    console.log(`Applying layout to the vulnerability compound node's children`);
            vulnerabilityCompoundNode.children().layout({
                name: 'cola',
                animate: true,
                padding: 30,
                spacingFactor: 1.5,
                fit: true,
                nodeDimensionsIncludeLabels: true
            }).run().promiseOn('layoutstop').then(() => {
                // Apply layout to the primary compound node's children
                if (mainCompoundNode && mainCompoundNode.children().length) {

		    console.log(`Apply the layout to the main compound node's children`);
                    mainCompoundNode.children().layout({
                        name: 'cola',
                        animate: true,
                        padding: 30,
                        spacingFactor: 1.5,
                        fit: true,
                        nodeDimensionsIncludeLabels: true
                    }).run().promiseOn('layoutstop').then(() => {
                        // Apply layout to the remaining nodes not in any compound
			console.log(`Apply breadthfirst layout to the remaining nodes`);
                        cy.nodes().filter('[parent = null]').layout({
                            name: 'breadthfirst',
                            directed: true,
                            padding: 60,
                            fit: true,
                            spacingFactor: 2.0,
                            animate: true,
                            roots: `[id = "${nodeId}"]`
                        }).run();
                    });
                }
            });
        } else if (mainCompoundNode && mainCompoundNode.children().length) {
            // Apply layout to primary compound node vulnerability compound doesn't exist

	    console.log(`First apply layout to main compound.`);
            mainCompoundNode.children().layout({
                name: 'cola',
                animate: true,
                padding: 30,
                spacingFactor: 1.5,
                fit: true,
                nodeDimensionsIncludeLabels: true
            }).run().promiseOn('layoutstop').then(() => {

		console.log('Then apply breadthfirst layout to primary nodes.');
                cy.nodes().filter('[parent = null]').layout({
                    name: 'breadthfirst',
                    directed: true,
                    padding: 60,
                    fit: true,
                    spacingFactor: 2.0,
                    animate: true,
                    roots: `[id = "${nodeId}"]`
                }).run();
            });
        } else {

	    console.log('Apply breadthfirst layout to Cytoscape nodes.');
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
	    adjustZoom();
	    layout.stop();
	    layout.run();
	}

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

function collapseNodesAndRecursiveNodes(nodeId) {
    console.log(`\nRemoving neighbors of node: ${nodeId}`);
    console.log('Expanded Nodes: ', expandedNodes);

    // Recursive collapse function for the node and its neighbors
    function recursiveCollapse(id) {
        // Check if neighbors exist and if the node was expanded
        if (!neighborSets[id] || !expandedNodes.has(id)) return;

        // Get the neighbors as an array of IDs
        const neighbors = Array.from(neighborSets[id]);

        // Iterate over neighbors in reverse order to remove them recursively
        for (let i = neighbors.length - 1; i >= 0; i--) {
            const currentNeighbor = neighbors[i];
            const currentNeighborId = currentNeighbor.data.id;
            // console.log('Current neighbor to remove:', currentNeighborId);

            // If currentNeighborId was independently expanded, collapse it recursively
            if (expandedNodes.has(currentNeighborId)) {
                recursiveCollapse(currentNeighborId);
                console.log(`Recursively collapsed neighbors for ${currentNeighborId}\n\n`);
            }

            // Remove the current neighbor node from Cytoscape
            const neighborNode = cy.getElementById(currentNeighborId);
            if (neighborNode) {

		console.log(`Removing neighbor node: ${neighborNode}`);
                cy.batch(() => {
                    neighborNode.remove();
                });
            }
        }

	// Check and remove compound nodes if they exist
	const compoundNodeId = `compound-${id}`;
	const vulnerabilityCompoundNodeId = `vulnerability-compound-${id}`;
	const compoundNode = cy.getElementById(compoundNodeId);
	const vulnerabilityCompoundNode = cy.getElementById(vulnerabilityCompoundNodeId);

	console.log(`Displayed Nodes: ${displayedNodeIDs}`);

        cy.batch(() => {
            if (compoundNode.length) {
                console.log(`Removing compound node: ${compoundNodeId}`);
                cy.remove(compoundNode);
            }

            if (vulnerabilityCompoundNode.length) {
                console.log(`Removing vulnerability compound node: ${vulnerabilityCompoundNodeId}`);
                cy.remove(vulnerabilityCompoundNode);
            }
        });

        // Update the virtual network on the middle layer
        fetch(`/api/collapse`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(neighbors)
        });

        // Clean up tracking of displayed nodes and expanded neighbors
        neighbors.forEach(neighbor => {
            delete displayedNodeIDs[neighbor.data.id];
        });

        delete neighborSets[id];
        expandedNodes.delete(id);
    }

    // Check if nodeId is the last expanded node to avoid redundant collapses
    const lastExpandedNodeId = Array.from(expandedNodes).pop();
    if (nodeId !== lastExpandedNodeId) {
        console.log(`\n${nodeId} is not the last expanded node. Collapsing recursively.\n\n`);
        recursiveCollapse(nodeId);
    } else {
        console.log('Collapsing only the last expanded node without recursion');

        // Collapse only nodeId’s immediate neighbors without recursion
        const neighbors = Array.from(neighborSets[nodeId] || []);
        console.log('\nCollapsing neighbors of the last expanded node:', neighbors);

        cy.batch(() => {
            neighbors.forEach(neighbor => {
                const neighborNode = cy.getElementById(neighbor.data.id);
                if (neighborNode) {
                    // console.log(`Removing ${neighborNode} from Cytoscape`);
                    neighborNode.remove();
                }
            });

	    // Remove compound nodes if they exist
	    const compoundNodeId = `compound-${nodeId}`;
	    const compoundNode = cy.getElementById(compoundNodeId);

	    if (compoundNode.length) {
		cy.remove(compoundNode);
	    }

	    const vulnerabilityCompoundNodeId = `vulnerability-compound-${nodeId}`;
	    const vulnerabilityCompoundNode = cy.getElementById(vulnerabilityCompoundNodeId);

	    if (vulnerabilityCompoundNode.length) {
		cy.remove(vulnerabilityCompoundNode);
	    }
        });

        fetch(`/api/collapse`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(neighbors)
        });

        // Clean up tracking of displayed nodes and expanded neighbors
        neighbors.forEach(neighbor => {
            delete displayedNodeIDs[neighbor.data.id];
        });

        // Clean up the neighbor sets and expanded nodes
        delete neighborSets[nodeId];
        expandedNodes.delete(nodeId);
    }

    // Apply layout to remaining nodes
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
    adjustZoom();
    layout.stop();
    layout.run();

    console.log(`Collapsed neighbors of ${nodeId}`);
}

    function calculateCVSSSeverity(nodeValue){
	if (nodeValue === 0.0) {
	    return 'NONE';
	} else if (nodeValue >= 0.1 && nodeValue <= 3.9) {
	    return 'LOW';
	} else if (nodeValue > 3.9 && nodeValue <= 6.9) {
            return 'MEDIUM';
        } else if (nodeValue > 6.9 && nodeValue <= 8.9) {
            return 'HIGH';
        } else if (nodeValue > 8.9 && nodeValue <= 10.0) {
            return 'CRITICAL';
        }
    }

    function adjustZoom() {
        const zoomFactor = Math.max(2.0, cy.nodes().length / 10);
	cy.maxZoom(zoomFactor);

        const containerWidth = cy.container().clientWidth;
        const containerHeight = cy.container().clientHeight;
        const minZoomFactor = Math.max(0.005, Math.min(containerWidth, containerHeight) / 1000);
        cy.minZoom(minZoomFactor);
        cy.fit();
    }

    let hoverTimeout;

    cy.on('mouseover', 'node', function (event) {
        const node = event.target;
	const nodeId = event.target.id();
	const nodeType = node.data('type');
	const riskValue = node.data('value');

	if ((nodeType === 'IP') && expandedNodes.has(nodeId)) {
	    hoverTimeout = setTimeout(() => {

	        // design the tooltip to be displayed
	        const tooltipContent = `
		    <div class="tooltip-content">
		        <p><b>Risk Factor:</b> ${riskValue || 'Not available'}</p>
		    </div>
	        `;

	        const tooltip = document.createElement('div');
	        tooltip.innerHTML = tooltipContent;
	        tooltip.classList.add('cy-tooltip');

	        document.body.appendChild(tooltip);

	        const { x, y } = node.renderedPosition();
	        const cyContainerRect = cy.container().getBoundingClientRect();
	        tooltip.style.left = `${x + cyContainerRect.left}px`;
	        tooltip.style.top = `${y + cyContainerRect.top}px`;

	        node.data('tooltip', tooltip);
	    }, 2000);
	}
    });

    cy.on('mouseout', 'node', function (event) {
	clearTimeout(hoverTimeout);

	const node = event.target;
	const tooltip = node.data('tooltip');
	if (tooltip) {
	    document.body.removeChild(tooltip);
	    node.removeData('tooltip');
	}
    });
}
