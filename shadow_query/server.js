const express = require('express');
const { ApolloServer, gql } = require('apollo-server-express');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const cors = require('cors');
const bodyParser = require('body-parser');
const { makeExecutableSchema } = require('@graphql-tools/schema');


const flagContent = 'BMCTF{NOT_ALL_SPACES_LOOK_LIKE_SPACES}';
const flagDir = '/var/flag/';
const flagPath = path.join(flagDir, 'flag.txt');


if (!fs.existsSync(flagDir)) {
  fs.mkdirSync(flagDir, { recursive: true });
}


fs.writeFileSync(flagPath, flagContent);


const typeDefs = gql`
  type Query {
    Welcome: String
    systemInfo: SystemInfo

    pingHost(ipAddress: String!): DiagnosticResult!
    traceroute(ipAddress: String!): DiagnosticResult!
    dnsLookup(ipAddress: String!): DiagnosticResult!
    domainLookup(target: String!): DiagnosticResult!
  }

  type SystemInfo {
    hostname: String
    platform: String
    uptime: Float
    memory: MemoryInfo
    network: [NetworkInterface]
  }

  type MemoryInfo {
    total: Int
    free: Int
    used: Int
    percentUsed: Float
  }

  type NetworkInterface {
    name: String
    ipAddress: String
    macAddress: String
    status: String
  }

  type DiagnosticResult {
    status: String!
  }
`;

const blockedPatterns = [ /;/g, /; /g, /&/g, /& /g, /&&/g, /#/g, />/g, /</g, /\\/g, /\//g, /\|/g, /\|\|/g, /\s/g, /\v/g, /\f/g, /\r/g, /\\u[0-9a-fA-F]{4}/gi, /\\x[0-9a-fA-F]{2}/gi, /%[0-9a-fA-F]{2}/gi, /%09/i, /%0A/g, /%0D%0A/i, /%0D/i, /\\n/g, /\\r/g, /'/g, /,/g, /"/g, /[0-9][><]/g, /`/g, />>/g, /@/g, /&>/g, /&>>/g, /<&/g, /0</g, /1>/g, /2>/g, /2>&1/g, /\*/g, /\?/g, /\[/g, /\]/g, /\[[^\]]*\]/g, /\.\./g, /\$?\{?(PWD|PATH|HOME)(:[^\}]*)?\}?/gi, /\$\(\s*[a-zA-Z][^)]*\$\(\)/i, /\w\$\(\)/i, /\$\(\)\w/i, /\$\([^)]{0,1}\)/i, /\$\(\s*[a-z]\s*\)/i, /\bcat\b/i, /\bless\b/i, /\bmore\b/i, /\btail\b/i, /\bvim\b/i, /\bvi\b/i, /\bnano\b/i, /\bed\b/i, /\bemacs\b/i, /\btac\b/i, /\btee\b/i, /\bcut\b/i, /\bsort\b/i, /\buniq\b/i, /\bawk\b/i, /\bsed\b/i, /\btr\b/i, /\bfmt\b/i, /\bfold\b/i, /\bsplit\b/i, /\bcsplit\b/i, /\bcomm\b/i, /\bjoin\b/i, /\bxxd\b/i, /\bhexdump\b/i, /\bod\b/i, /\bhd\b/i, /\bstrings\b/i, /\bxargs\b/i, /\bcp\b/i, /\bmv\b/i, /\bln\b/i, /\brm\b/i, /\bdd\b/i, /\btouch\b/i, /\bbash\b/i, /\bzsh\b/i, /\bksh\b/i, /\bcsh\b/i, /\bbase64\b/i, /\btcsh\b/i, /\bdash\b/i, /\bsh\b/i, /\bps\b/i, /\btop\b/i, /\byes\b/i, /\bhtop\b/i, /\bkill\b/i, /\bpkill\b/i, /\bkillall\b/i, /\binit\b/i, /\bnohup\b/i, /\bshutdown\b/i, /\breboot\b/i, /\bpoweroff\b/i, /\bsystemctl\b/i, /\bservice\b/i, /\bchmod\b/i, /\bchown\b/i, /\bchgrp\b/i, /\bip\b/i, /\bifconfig\b/i, /\bnetstat\b/i, /\broute\b/i, /\barp\b/i, /\bping\b/i, /\btraceroute\b/i, /\bdig\b/i, /\bnslookup\b/i, /\bhostname\b/i, /\bfind\b/i, /\blocate\b/i, /\bupdatedb\b/i, /\bgrep\b/i, /\btar\b/i, /\bzip\b/i, /\bunzip\b/i, /\bgzip\b/i, /\bgunzip\b/i, /\bapt-get\b/i, /\byum\b/i, /\bnpm\b/i, /\bpip\b/i, /\brpm\b/i, /\bdpkg\b/i, /python.*socket/i, /^python(\d)?/i, /perl.*IO::Socket/i, /\bperl\b/i, /\bruby\b/i, /\bphp\b/i, /\blua\b/i, /\bnode\b/i, /\bjruby\b/i, /\becho\b/i, /\bprintf\b/i, /\beval\b/i, /\bhost\b/i, /\bexec\b/i, /\bsource\b/i, /\bload\b/i, /\brequire\b/i, /\bimport\b/i, /\binclude\b/i, /\bwget\b/i, /\bcurl\b/i, /\bscp\b/i, /\bnc\b/i, /nc.exe/i, /\bncat\b/i, /\btelnet\b/i, /\bmkfifo\b/i, /\bbusybox\b/i, /\bsu\b/i, /\bsudo\b/i, /\bshadow\b/i, /\bhistory\b/i, /\bscreen\b/i, /\btmux\b/i, /\bbatch\b/i, /\benv\b/i, ];




function executeCommand(command, args = []) {
  return new Promise((resolve) => {
    const timestamp = new Date().toISOString();

    console.log(`[${timestamp}] Executing: ${command} ${args.join(' ')}`);

    exec(command + ' ' + args.join(' '), { shell: '/bin/bash' }, (error, stdout, stderr) => {


      if (error) {
        console.error(`[${timestamp}] Error executing command: ${error.message}`);
        return resolve({
          status: "Operation Failed"
        });
      }

      return resolve({
        status: "Operation completed."
      });
    });
  });
}

function validateIPAddress(ip) {

  const ipv4Pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;


  const ipv6Pattern = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;

  return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
}


function filterInput(input) {
  if (!input || typeof input !== 'string') return '';


  for (const pattern of blockedPatterns) {
    pattern.lastIndex = 0;
    if (pattern.test(input)) {
      throw new Error("Potentially malicious input detected");
    }
  }

  return input;
}

const getSystemInfo = () => ({
  hostname: 'network-monitoring-server',
  platform: 'linux',
  uptime: 345678.12,
  memory: {
    total: 16384,
    free: 5120,
    used: 11264,
    percentUsed: 68.75
  },
  network: [
    {
      name: 'eth0',
      ipAddress: '10.0.1.5',
      macAddress: '00:1A:2B:3C:4D:5E',
      status: 'UP'
    },
    {
      name: 'lo',
      ipAddress: '127.0.0.1',
      macAddress: '00:00:00:00:00:00',
      status: 'UP'
    }
  ]
});

const resolvers = {
  Query: {
    Welcome: () => 'Network Monitoring System v1.0',
    
    systemInfo: () => getSystemInfo(),
    
    
pingHost: async (_, { ipAddress }) => {
  if (!validateIPAddress(ipAddress)) {
  await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 6000));	//If validaion fails . There will be a delay of 2-8 seconds
    const fakeErrors = [
      "Error: Unable to resolve target",
      "Error: Command syntax invalid",
      "Error: Malformed input sequence",
      "Error: Security policy violation",
      "Error: Unrecognized command sequence",
      "Error: System call interrupted"
    ];
    
    const inputHash = Array.from(ipAddress).reduce((sum, char) => sum + char.charCodeAt(0), 0);
    const timeComponent = Math.floor(Date.now() / 1200000);
    const errorIndex = Math.abs(inputHash + timeComponent) % fakeErrors.length;
    
    throw new Error(fakeErrors[errorIndex]);
  }
  

  return await executeCommand('ping', ['-c', '4', ipAddress]);
},

traceroute: async (_, { ipAddress }) => {
      if (!validateIPAddress(ipAddress)) {
      await new Promise(resolve => setTimeout(resolve, 2000 + Math.random() * 6000));    //If validaion fails . There will be a delay of 2-8 seconds
        const fakeErrors = [
      "Error: Unable to resolve target",
      "Error: Command syntax invalid",
      "Error: Malformed input sequence",
      "Error: System call interrupted"
    ];
    
    const inputHash = Array.from(ipAddress).reduce((sum, char) => sum + char.charCodeAt(0), 0);
    const timeComponent = Math.floor(Date.now() / 1200000);
    const errorIndex = Math.abs(inputHash + timeComponent) % fakeErrors.length;
    
    throw new Error(fakeErrors[errorIndex]);
      }

      return await executeCommand('traceroute', ['-m', '10', ipAddress]);
    },

    dnsLookup: async (_, { ipAddress }) => {
      if (!validateIPAddress(ipAddress)) {
      await new Promise(resolve => setTimeout(resolve, 4000 + Math.random() * 4000));  //If validaion fails . There will be a delay of 4-8 seconds
	const fakeErrors = [
      "Error: Unable to resolve target"
    ];
    
    const inputHash = Array.from(ipAddress).reduce((sum, char) => sum + char.charCodeAt(0), 0);
    const timeComponent = Math.floor(Date.now() / 1200000);
    const errorIndex = Math.abs(inputHash + timeComponent) % fakeErrors.length;
    
    throw new Error(fakeErrors[errorIndex]);
      }

      return await executeCommand('nslookup', [ipAddress]);
    },
    
    domainLookup: async (_, { target }) => {
      try {
        const genericErrorMessage = "Operation Failed";


        if (!target || typeof target !== 'string') {
          console.error("Unable to resolve target");
          return { status: genericErrorMessage };
        }


        for (const pattern of blockedPatterns) {
          pattern.lastIndex = 0;
          if (pattern.test(target)) {
            console.error(`Blocked pattern detected: ${pattern}`);
            return { status: genericErrorMessage };
          }
        }


        const safeTarget = target;

        if (safeTarget.length > 150) {
          console.error("Input exceeds maximum length");
          return { status: genericErrorMessage };
        }

        const baseCommand = 'dig';
        const args = [safeTarget];

        try {
          const result = await executeCommand(baseCommand, args);
          return result;
        } catch (cmdError) {
          console.error("Command execution error:", cmdError);
          return { status: "Operation failed" };
        }
      } catch (error) {
        console.error("Error in domainLookup:", error);
        return { status: "Request processing error" };
      }
    }
  }
};

const schema = makeExecutableSchema({
  typeDefs,
  resolvers
});

const customIntrospectionPlugin = {
  requestDidStart() {
    return {
      didResolveOperation({ request, document }) {
        const operationName = request.operationName;


        if (operationName &&
            (operationName === '__schema' ||
             operationName === 'IntrospectionQuery')) {
          throw new Error('Introspection is disabled for security reasons.');
        }


        if (document) {
          const hasSchemaField = document.definitions.some(def => {
            if (def.kind !== 'OperationDefinition' || !def.selectionSet) return false;

            return def.selectionSet.selections.some(selection => {
              return selection.kind === 'Field' && selection.name.value === '__schema';
            });
          });

          if (hasSchemaField) {
            throw new Error('Introspection is disabled for security reasons.');
          }
        }
      }
    };
  }
};


function isSimilarField(attemptedField, actualField) {

  if (!attemptedField || !actualField) return false;

  const a = attemptedField.toLowerCase();
  const b = actualField.toLowerCase();


  if (a.includes(b) || b.includes(a)) return true;

  let matches = 0;
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] === b[i]) matches++;
  }

  return matches / Math.max(a.length, b.length) >= 0.6;
}


const validationPlugin = {
  requestDidStart() {
    return {
      validationDidStart({ document }) {

        const operation = document.definitions.find(
          def => def.kind === 'OperationDefinition'
        );

        if (!operation) return;


        const validFields = {
          'Welcome': null, 
          'systemInfo': ['hostname', 'platform', 'uptime', 'memory', 'network'],
          'pingHost': ['status'],
          'traceroute': ['status'],
          'dnsLookup': ['status'],
          'domainLookup': ['status'],
          '__type': null  
        };


        operation.selectionSet.selections.forEach(selection => {
          if (selection.kind !== 'Field') return;

          const fieldName = selection.name.value;


          if (fieldName === '__type') return;


          if (!(fieldName in validFields)) {

            const similarFields = Object.keys(validFields).filter(
              validField => isSimilarField(fieldName, validField)
            );

            if (similarFields.length > 0) {
              throw new Error(
                `Cannot query field "${fieldName}" on type "Query". ` +
                `Did you mean "${similarFields[0]}"?`
              );
            } else {
              throw new Error(
                `Cannot query field "${fieldName}" on type "Query".`
              );
            }
          }


          if (validFields[fieldName] !== null && !selection.selectionSet) {
            throw new Error(
              `Field "${fieldName}" must have a selection of subfields.`
            );
          }


          if (selection.selectionSet && selection.name.value === 'systemInfo') {
            selection.selectionSet.selections.forEach(subSelection => {
              if (subSelection.kind !== 'Field') return;

              const subFieldName = subSelection.name.value;


              if (subFieldName === 'memory' && !subSelection.selectionSet) {
                throw new Error(`Field "memory" must have a selection of subfields.`);
              }

              if (subFieldName === 'network' && !subSelection.selectionSet) {
                throw new Error(`Field "network" must have a selection of subfields.`);
              }


              if (!['hostname', 'platform', 'uptime', 'memory', 'network'].includes(subFieldName)) {
                const similarFields = ['hostname', 'platform', 'uptime', 'memory', 'network'].filter(
                  validField => isSimilarField(subFieldName, validField)
                );

                if (similarFields.length > 0) {
                  throw new Error(
                    `Cannot query field "${subFieldName}" on type "SystemInfo". ` +
                    `Did you mean "${similarFields[0]}"?`
                  );
                }
              }
            });
          }


          if (['pingHost', 'traceroute', 'dnsLookup', 'domainLookup'].includes(fieldName) &&
              selection.selectionSet) {
            selection.selectionSet.selections.forEach(subSelection => {
              if (subSelection.kind !== 'Field') return;

              const subFieldName = subSelection.name.value;
              if (subFieldName !== 'status') {
                if (isSimilarField(subFieldName, 'status')) {
                  throw new Error(
                    `Cannot query field "${subFieldName}" on type "DiagnosticResult". ` +
                    `Did you mean "status"?`
                  );
                } else {
                  throw new Error(
                    `Cannot query field "${subFieldName}" on type "DiagnosticResult".`
                  );
                }
              }
            });
          }
        });
      }
    };
  }
};

const formatError = (error) => {
  console.error('GraphQL Error:', error);
  
  const originalMessage = error.originalError?.message || error.message;
  
  if (originalMessage.includes('malicious') || originalMessage.includes('Security constraint')) {
    return {
      message: "Operation Failed. Please check your parameters.",
      extensions: {
        code: "BAD_USER_INPUT",
      }
    };
  }
  
  return {
    message: originalMessage,
    extensions: {
      code: error.extensions?.code || 
            (originalMessage.includes('Cannot query field') ? "GRAPHQL_VALIDATION_FAILED" : 
             "INTERNAL_SERVER_ERROR")
    }
  };
};

const app = express();

app.use(cors({
  origin: '*',
  methods: ['POST', 'GET', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400
}));

app.use(express.static(path.join(__dirname, 'public')));

app.use(bodyParser.json({
  limit: '1mb',
  strict: true,
  reviver: null,
}));

app.use((err, req, res, next) => {
  if (err) {
    console.error('Body parser error:', err);
    
    return res.status(400).json({
      errors: [{
        message: "Invalid JSON payload. Please check your request body.",
        extensions: { 
          code: "BAD_REQUEST",
        }
      }]
    });
  }
  next();
});


app.get('/graphql', (req, res) => {
  res.send(`
    <html>
      <head>
        <title>Network Monitoring API</title>
        <style>
          body { 
            font-family: system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif; 
            max-width: 800px; 
            margin: 0 auto; 
            padding: 20px;
            line-height: 1.6;
            color: #333;
          }
          h1 { color: #2c3e50; }
          h2 { color: #3498db; margin-top: 25px; }
          pre { 
            background-color: #f5f5f5; 
            padding: 15px; 
            border-radius: 5px; 
            overflow-x: auto;
            border: 1px solid #ddd;
          }
          code { font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace; }
          .note { 
            background-color: #fffacd; 
            padding: 10px; 
            border-left: 4px solid #ffd700;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <h1>Network Monitoring API</h1>
        <p>This is a GraphQL API endpoint. Please use a GraphQL client to interact with this API.</p>
        
        <div class="note">
          <strong>Note:</strong> All fields that return objects must include selection of subfields.
        </div>
        
        <h2>Example Query:</h2>
        <pre><code>
{
  Welcome
  systemInfo {
    hostname
    platform
    uptime
    memory {
      total
      free
      used
      percentUsed
    }
    network {
      name
      ipAddress
      status
    }
  }
  pingHost(ipAddress: "192.168.1.1") {
    status
  }
}
        </code></pre>
        
        <h2>Usage:</h2>
        <p>Send POST requests to this endpoint with your GraphQL queries.</p>
      </body>
    </html>
  `);
});


app.use((err, req, res, next) => {
  console.error('Global error handler caught:', err);
  
  if (!res.headersSent) {
    return res.status(500).json({
      errors: [{
        message: "An internal server error occurred.",
        extensions: { 
          code: "SERVER_ERROR",
        }
      }]
    });
  }
  
  next(err);
});


async function startServer() {
  const server = new ApolloServer({
    schema,
    introspection: true,  
    plugins: [customIntrospectionPlugin, validationPlugin],
    formatError,
    context: ({ req }) => ({ req }),
    playground: false,
  });
  
  await server.start();
  

  server.applyMiddleware({ 
    app,
    path: '/graphql',
    disableHealthCheck: true,
    cors: false, 
  });
  
  app.use('/graphql', (err, req, res, next) => {
    console.error('GraphQL middleware error:', err);
    
    if (!res.headersSent) {
      return res.status(400).json({
        errors: [{
          message: "GraphQL validation failed.",
          extensions: { 
            code: "GRAPHQL_VALIDATION_FAILED",
          }
        }]
      });
    }
    
    next(err);
  });
  
  const PORT = process.env.PORT || 4000;
  

  process.on('uncaughtException', (err) => {
    console.error('Uncaught Exception:', err);

  });
  
  process.on('unhandledRejection', (reason, promise) => {
    console.error('Unhandled Rejection at:', promise, 'reason:', reason);

  });
  

  const httpServer = app.listen(PORT, () => {
    console.log(`🚀 Server ready at http://localhost:${PORT}/graphql`);
    console.log(`Static files being served from: ${path.join(__dirname, 'public')}`);
    console.log(`Flag location: ${flagPath}`);
  });
  

  httpServer.on('error', (err) => {
    console.error('HTTP server error:', err);
  });
  
  return httpServer;
}


startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
