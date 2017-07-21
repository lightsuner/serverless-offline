'use strict';

const Boom = require('boom');

const createLambdaContext = require('./createLambdaContext');
const functionHelper = require('./functionHelper');
const debugLog = require('./debugLog');
const resetEnvVariables = require('./resetEnvVariables');
const toPlainOrEmptyObject = require('./utils').toPlainOrEmptyObject;

module.exports = function createAuthScheme(authFun, funRuntime, funName, endpointPath, options, serverlessLog) {
  const authFunName = authFun.name;

  // Get Auth Function object with variables
  let populatedAuthFun;
  try {
    populatedAuthFun = authFun.toObjectPopulated({
      stage: options.stage,
      region: options.region,
    });
  } catch (err) {
    debugLog(`Error while populating function '${authFunName}' with stage '${options.stage}' and region '${options.region}':`);
    throw err;
  }

  const authorizerOptions = populatedAuthFun.authorizer;
  if (authorizerOptions.type !== 'TOKEN') {
    throw new Error(`Authorizer Type must be TOKEN (λ: ${authFunName})`);
  }

  const identitySourceMatch = /^method.request.header.(\w+)$/.exec(authorizerOptions.identitySource);
  if (!identitySourceMatch || identitySourceMatch.length !== 2) {
    throw new Error(`Serverless Offline only supports retrieving tokens from the headers (λ: ${authFunName})`);
  }

  const identityHeader = identitySourceMatch[1].toLowerCase();

  const funOptions = functionHelper.getFunctionOptions(authFun, populatedAuthFun);

  // Create Auth Scheme
  return () => ({

    authenticate(request, reply) {
      console.log(''); // Just to make things a little pretty
      serverlessLog(`Running Authorization function for ${request.method} ${request.path} (λ: ${authFunName})`);

      // Get Authorization header
      const req = request.raw.req;
      const authorization = req.headers[identityHeader];

      debugLog(`Retrieved ${identityHeader} header ${authorization}`);

      // Create event Object for authFunction
      //   methodArn is the ARN of the function we are running we are authorizing access to (or not)
      //   Account ID and API ID are not simulated
      const event = {
        type: 'TOKEN',
        authorizationToken: authorization,
        methodArn: `arn:aws:execute-api:${options.region}:<Account id>:<API id>/${options.stage}/${funName}/${endpointPath}`,
      };

      // Set environment variables
      const newEnvVars = toPlainOrEmptyObject(populatedAuthFun.environment);
      resetEnvVariables(this.envVars, newEnvVars);
      this.envVars = newEnvVars;

      // Create the Authorization function handler
      let handler;

      try {
        handler = functionHelper.createHandler(funRuntime, funOptions, options);
      } catch (err) {
        return reply(Boom.badImplementation(err, `Error while loading ${authFunName}`));
      }

      // Creat the Lambda Context for the Auth function
      const lambdaContext = createLambdaContext(authFun, (err, result) => {
        // Return an unauthorized response
        const onError = (error) => {
          serverlessLog(`Authorization function returned an error response: (λ: ${authFunName})`, error);
          return reply(Boom.unauthorized('Unauthorized'));
        };

        if (err) {
          return onError(err);
        }

        const onSuccess = (policy) => {

          const jsonPolicy = JSON.stringify(policy);

          const invalidSymbolPosition = jsonPolicy.indexOf('\\"');

          if (invalidSymbolPosition !== -1) {
            serverlessLog(`Invalid auth data at position ${invalidSymbolPosition}: (λ: ${authFunName})`, err);
            return reply(Boom.badImplementation(`Invalid auth data at position ${invalidSymbolPosition}. Data: ${jsonPolicy}`));
          }

          // Validate that the policy document has the principalId set
          if (!policy.principalId) {
            serverlessLog(`Authorization response did not include a principalId: (λ: ${authFunName})`, err);
            return reply(Boom.forbidden('No principalId set on the Response'));
          }

          if (typeof policy.principalId !== 'string') {
            serverlessLog(`Authorization response error: principalId can be only a String: (λ: ${authFunName})`, err);
            return reply(Boom.badImplementation('principalId is not a string'));
          }

          const continueData = { credentials: { user: policy.principalId } };

          if (policy.context) {
            for (const key in policy.context) {
              if (!Object.prototype.hasOwnProperty.call(policy.context, key)) {
                continue;
              }

              const allowedTypes = ['number', 'string', 'boolean'];
              const keyType = typeof policy.context[key];

              if (!allowedTypes.includes(keyType)) {
                serverlessLog(`Context key ${key} has type ${keyType}, allowed only (${allowedTypes.join(', ')}): (λ: ${authFunName})`, err);
                return reply(Boom.badImplementation('Not allowed context key ${keyType}'));
              }
            }

            // set context data
            continueData.credentials.context = policy.context;
          }

          serverlessLog(`Authorization function returned a successful response: (λ: ${authFunName})`, policy);

          // Set the credentials for the rest of the pipeline
          return reply.continue(continueData);
        };

        if (result && typeof result.then === 'function' && typeof result.catch === 'function') {
          debugLog('Auth function returned a promise');
          result.then(onSuccess).catch(onError);
        } else if (result instanceof Error) {
          onError(result);
        } else {
          onSuccess(result);
        }
      });

      // Execute the Authorization Function
      handler(event, lambdaContext, lambdaContext.done);
    },
  });
};
