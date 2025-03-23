import jwt from 'jsonwebtoken';

// By default, API Gateway authorizations are cached (TTL) for 300 seconds.
// This policy will authorize all requests to the same API Gateway instance where the
// request is coming from, thus being efficient and optimising costs.
const generatePolicy = (principalId, methodArn) => {
  const apiGatewayWildcard = methodArn.split('/', 2).join('/') + '/*';

  return {
    principalId,
    policyDocument: {
      Version: '2012-10-17',
      Statement: [
        {
          Action: 'execute-api:Invoke',
          Effect: 'Allow',
          Resource: apiGatewayWildcard,
        },
      ],
    },
  };
};

export async function handler(event, context) {
  if (!event.authorizationToken) {
    throw 'Unauthorized';
  }

  console.log("event", event);
  console.log("context", context);

  const token = event.authorizationToken.replace('Bearer ', '');
  console.log("token", token);
  try {
    const claims = jwt.verify(token, process.env.AUTH0_PUBLIC_KEY);
    const policy = generatePolicy(claims.sub, event.methodArn);

    console.log("claims", claims);
    return {
      ...policy,
      context: claims
    };
  } catch (error) {
    console.log(error);
    throw 'Unauthorized';
  }
};
