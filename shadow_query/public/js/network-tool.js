document.addEventListener('DOMContentLoaded', function () {
    setupNetworkTools();
});

function setupNetworkTools() {
    const pingBtn = document.getElementById('ping-btn');
    if (pingBtn) {
        pingBtn.addEventListener('click', async () => {
            const ip = document.getElementById('ping-ip').value.trim();
            if (!ip) {
                showError('ping-results', 'Please enter an IP address');
                return;
            }

            const query = `query {
                pingHost(ipAddress: "${ip}") {
                    status
                }
            }`;

            const data = await executeGraphQLQuery(query);
            if (data.error) {
                showError('ping-results', data.error);
            } else {
                document.getElementById('ping-results').textContent = data.pingHost.status;
            }
        });
    }

    const tracerouteBtn = document.getElementById('traceroute-btn');
    if (tracerouteBtn) {
        tracerouteBtn.addEventListener('click', async () => {
            const ip = document.getElementById('traceroute-ip').value.trim();
            if (!ip) {
                showError('traceroute-results', 'Please enter an IP address');
                return;
            }

            const query = `query {
                traceroute(ipAddress: "${ip}") {
                    status
                }
            }`;

            const data = await executeGraphQLQuery(query);
            if (data.error) {
                showError('traceroute-results', data.error);
            } else {
                document.getElementById('traceroute-results').textContent = data.traceroute.status;
            }
        });
    }

    const dnsBtn = document.getElementById('dns-btn');
    if (dnsBtn) {
        dnsBtn.addEventListener('click', async () => {
            const ip = document.getElementById('dns-ip').value.trim();
            if (!ip) {
                showError('dns-results', 'Please enter an IP address');
                return;
            }

            const query = `query {
                dnsLookup(ipAddress: "${ip}") {
                    status
                }
            }`;

            const data = await executeGraphQLQuery(query);
            if (data.error) {
                showError('dns-results', data.error);
            } else {
                document.getElementById('dns-results').textContent = data.dnsLookup.status;
            }
        });
    }
}

async function executeGraphQLQuery(query) {
    try {
        const response = await fetch('/graphql', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
            body: JSON.stringify({ query })
        });

        if (!response.ok) {
            throw new Error('Failed to fetch data from server');
        }

        const result = await response.json();

        if (result.errors) {
            return { error: result.errors[0].message };
        }

        return result.data;
    } catch (error) {
        console.error('GraphQL Error:', error);
        return { error: 'An error occurred while processing your request.' };
    }
}

function showError(elementId, message) {
    const element = document.getElementById(elementId);
    if (element) {
        element.textContent = message;
        element.style.color = '#e74c3c';
        setTimeout(() => {
            element.style.color = '';
        }, 3000);
    }
}
