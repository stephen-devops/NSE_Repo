document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Initial supernet value
        let supernet = "147.251.96.0/23";

        // List of available CIDR supernets
        const cidrVals = ["147.251.96.0/21", "147.251.96.0/22", "147.251.96.0/23", "147.251.96.0/24",
		"147.251.96.0/25", "147.251.96.0/26", "147.251.96.0/27"];

        // Reference to the dropdown select element
        const cidrSelect = document.getElementById('cidrSelect');

        // Populate the dropdown with options
        cidrVals.forEach(cidr => {
            const option = document.createElement('option');
            option.value = cidr;
            option.textContent = cidr;
            cidrSelect.appendChild(option);
        });

        // Set the initial dropdown value
        cidrSelect.value = supernet;

        // Fetch the virtual network data
        let elements = await fetchVirtualNetworkData();

        // Call the visualization with the initial supernet
        initializeD3Visualization(supernet, elements);

        // Add event listener to handle selection changes
        cidrSelect.addEventListener('change', (event) => {
            newSupernet = event.target.value; // Update the selected supernet

            // Re-render the visualization with the new supernet
            initializeD3Visualization(newSupernet, elements);
        });
    } catch (error) {
        console.error('Error loading the virtual network data:', error);
    }
});

// Helper function to fetch virtual network data
async function fetchVirtualNetworkData() {
    const response = await fetch('/api/virtualNetwork');
    const elements = await response.json();

    // If the response is empty, trigger the initial data fetch
    if (!elements || elements.length === 0) {
        console.log('Fetching CIDR data');
        await fetch('/api/fetch-data');

        // Retry fetching the virtual network data after initial fetch
        const newResponse = await fetch('/api/virtualNetwork');
        return await newResponse.json();
    }
    return elements;
}

async function initializeD3Visualization(supernet, data) {

    const svgHeight = 420;
    const values = data[0].data['details'];
    const vulns = data[0].data['vulns'];

    // define your own data
    cidrDict = {};

    const initialLabel = 'neo4j';
    const newLabel = 'my_pool';

    values.forEach(val => {

	// check if node is vulnerable
	if (vulns.includes(val)){

	    cidrDict[val] = {
	    	value: val,
	    	label: initialLabel,
		vuln: 1
	    };
	} else {

	    cidrDict[val] = {
		value: val,
		label: initialLabel,
		vuln: 0
	    };
	}
    });

    let superLabel = newLabel;

    Object.entries(cidrDict).forEach(([key, value]) => {

	if (value.value === supernet){
	    superLabel = value.label;
	}
    });

    const { treemap, cidrSuffixes } = await fetchCIDRTreemap(supernet, cidrDict);

    // wrap the cidr values in a root value, a root CIDR range
    cidrHierarchy = wrapAsHierarchy(treemap, supernet, superLabel);

    // define a treemap visualization using the resulting data hierarchy
    const treemapSVG = createTreemapSVG(cidrHierarchy, cidrSuffixes, svgHeight);

    // Render the treemap SVG in the container
    const container = document.getElementById('treemapContainer');
    container.innerHTML = '';
    container.innerHTML = treemapSVG;
    return; // Skip rendering as a standard node

    async function fetchCIDRTreemap(supernet, cidrDict) {
    	const response = await fetch('/api/build-cidr-treemap', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ supernet, cidrDict }),
    	});

    	if (!response.ok) {
            throw new Error('Failed to fetch CIDR treemap.');
    	}

    	return await response.json();
    }

    // define afunction to wrap flat hierarchy in a root node
    function wrapAsHierarchy(flatData, rootCidr, rootLabel) {
	// Create a root object
        const rootNode = {
            cidr: rootCidr,
	    label: rootLabel,
            children: []
        };

        // Helper function to recursively build hierarchy
        function addChildToParent(parent, child) {
            if (!parent.children) parent.children = [];
            parent.children.push(child);
        }

        // Map of CIDR to node for quick lookup
        const cidrMap = {};

        // Add all items as nodes in the map
        Object.entries(flatData).forEach(([key, value]) => {
            const node = { ...value, cidr: key }; // Add CIDR to node
            cidrMap[key] = node;
        });

        // Build hierarchy by associating nodes as children
        Object.entries(flatData).forEach(([key, value]) => {
            if (value.children && value.children.length > 0) {
                value.children.forEach(child => {
                    if (cidrMap[child.cidr]) {
                        addChildToParent(cidrMap[key], cidrMap[child.cidr]);
                    }
                });
            }
        });

        // Add top-level nodes under the root
        Object.values(cidrMap).forEach(node => {
            if (!node.parent) {
                addChildToParent(rootNode, node);
            }
        });

        return rootNode;
    }

    function createTreemapSVG(treeHierarchy, cidrSuffixes, height) {
    	const margin = 10; // Margin around the SVG content

    	// Row headings
	const cidrHeadings = [];

	cidrSuffixes.forEach(suffix => {

	    let res = '/'.concat(suffix);
	    cidrHeadings.push(res);
	});

	cidrHeadings.push('Host IP');

    	const numRows = cidrHeadings.length;
    	const rowHeight = height / numRows; // Divide the height into rows

    	const fixedNodeWidth = 30; // Fixed width for leaf nodes
    	const additionalLeftSpace = 10;

    	// Convert the data to a D3 hierarchy object
    	const root = d3.hierarchy(treeHierarchy);

	// return the lowest depth of the treemap
	dataHeight = root.height;

    	// Recursive function to compute mutable widths
    	const computeWidths = (node) => {

            if (!node.children || node.children.length === 0) {

            	// Leaf node: assign fixed width
            	node.width = fixedNodeWidth;
            } else {

            	// Internal node: sum the widths of its children
            	node.width = node.children.reduce((total, child) => {

                    computeWidths(child); // Recursively calculate child's width
                    return total + child.width;
            	}, 0);
            }
    	};

    	// Call the recursive function to compute widths
	console.log('computeWidths function: ', root);
    	computeWidths(root);

	const customTiling = (node, x0, y0) => {

    	    // Modify properties based on the conditions
    	    if (node.data && node.data.cidr) {
        	const cidr = node.data.cidr;

        	if (cidr.endsWith("/30") || cidr.endsWith("/31")) {

           	    const parts = cidr.split('.');

            	    if (parts.length >= 4) {

                	node.data.cidr = parts[3]; // Take the last segment
            	    }

        	} else if (cidr.endsWith("/32")) {

            	    node.data.cidr = "IP"; // Set to "IP"

            	    const vuln = node.data.vuln;

            	    if (vuln !== undefined) {

                	if (vuln === 1) {

                    	    node.data.color = "crimson"; // Mark vulnerable hosts
                	} else {

                    	    node.data.color = "aqua"; // Mark safe hosts
                	}
            	    }
        	}
    	    }

    	    // Propagate "crimson" color up to three levels
    //	    const propagateColor = (childNode, levels) => {

      //  	if (levels === 0 || !childNode.parent) return;

        //	const childColor = childNode.data?.color;

        //	if (childColor === "crimson") {

          //  	    if (childNode.parent.data.label !== "neo4j") {

            //    	childNode.parent.data.color = "crimson";
	//	    }

          //  	    propagateColor(childNode.parent, levels - 1); // Recur for parent
        //	}
    	  //  };

    	    // Trigger propagation if this node is "crimson"
//    	    if (node.data?.color === "crimson") {

  //      	propagateColor(node, 2); // Start propagation for this node
    //	    }

    	    // Base case: Add "Free" nodes for leaf nodes
    	    if (!node.children || !node.children.length) {

		const leafDepth = node.depth;

        	if (leafDepth < dataHeight) {

            	    const childDepth = leafDepth + 1;

            	    const newNode = {

                	data: { cidr: "Free" },
                	depth: childDepth,
                	parent: node,
                	value: 1,
                	width: fixedNodeWidth, // Fixed width for "Free" leaf nodes
            	    };

            	    node.children = [newNode];

            	    const childX0 = x0;
            	    const childY0 = y0 + rowHeight;

            	    customTiling(newNode, childX0, childY0);
            	}
    	    }

    	    // Set coordinates for the node
    	    node.x0 = x0;
    	    node.y0 = y0;
    	    node.x1 = x0 + node.width;
    	    node.y1 = y0 + rowHeight;

    	    // Recursively position child nodes
    	    if (node.children) {

        	let currentX = x0;
        	node.children.forEach((child) => {

            	    customTiling(child, currentX, y0 + rowHeight);
            	    currentX += child.width; // Position the next child
        	});
    	    }
	};

    	customTiling(root, 0, 0);

    	const finalWidth = root.width + additionalLeftSpace; // Total SVG width

    	// Create SVG
    	const svg = d3.create('svg')
            .attr("viewBox", `-${additionalLeftSpace} -10 ${finalWidth + 10} ${height + 10}`) // Adjust for additional space
            .attr('width', finalWidth)
            .attr('height', height)
            .style('font', '12px sans-serif');

    	// Add rectangles for each node
    	svg.selectAll('rect')
            .data(root.descendants())
            .join('rect')
            .attr('x', d => d.x0)
            .attr('y', d => d.y0)
            .attr('width', d => d.width)
            .attr('height', rowHeight)
            .attr('fill', d => {

            	if (d.data.color) return d.data.color; // Use custom color if defined
            	if (d.children && d.data.label === "neo4j") return 'steelblue'; // Neo4 parent nodes
		if (d.children && d.data.label === "my_pool") return 'lightgray'; // My pools

            	return 'lightgray'; // Default for "Free"
            })
            .attr('stroke', 'white');

    	// Add text labels
    	svg.selectAll('text')
            .data(root.descendants())
            .join('text')
            .attr('x', d => (d.x0 + d.x1) / 2)
            .attr('y', d => d.y0 + rowHeight / 2)
            .attr('dy', '0.35em')
            .attr('text-anchor', 'middle')
            .text(d => d.data.cidr || "Free")
            .attr('fill', d => {
		if (d.data.label ===  "neo4j" || d.data.color === "crimson") return 'white';
		if (d.data.color === "aqua") return 'black';
		return 'black';
	    })
	    .style('font-size', d => {
	        const cidr = d.data.cidr || "";
	    	if (cidr.endsWith("/30") || cidr.endsWith("/31")) {
            	    return '8px';
		}
		return '10px';
	    });

    	// Add row headings
    	svg.selectAll('.heading')
            .data(cidrHeadings)
            .join('text')
            .attr('class', 'heading')
            .attr('x', -10) // Position headings to the left of the treemap
            .attr('y', (d, i) => (i + 0.5) * rowHeight) // Center headings vertically in each row
            .attr('dy', '0.35em')
            .attr('text-anchor', 'end') // Align text to the right
            .attr('fill', 'black')
            .style('font-weight', 'bold')
            .text(d => d);

    	return svg.node().outerHTML; // Return SVG as a string
    }
}
