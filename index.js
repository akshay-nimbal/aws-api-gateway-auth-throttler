const jsonwebtoken = require("jsonwebtoken");
const RateLimiter = require("async-ratelimiter");
const Redis = require("ioredis");

const rateLimiter = new RateLimiter({
  db: new Redis({
    port: process.env.REDIS_PORT,
    host: process.env.REDIS_HOST,
    connectTimeout: 10000,
  }),
});

exports.handler = async (event, context, callback) => {
  console.log("event : ", event);
  let tkn = event.headers.Authorization;
  let status = "deny";
  let authtoken = tkn.split(" ")[1];
  const publicKey = `-----BEGIN PUBLIC KEY-----\n${process.env.PUBLIC_KEY}\n-----END PUBLIC KEY-----`;
  let message = "";
  const verifyOptions = {
    algorithm: ["RS256"],
  };
  let payload;
  try {
    payload = await jsonwebtoken.verify(authtoken, publicKey, verifyOptions);
    console.log("payload: " + JSON.stringify(payload));
    status = "allow";
    const limit = await rateLimiter.get({
      id: payload.clientId,
      duration: process.env.DURATION,
      max: process.env.MAX_REQUESTS,
    });
    console.log("Id :: ", payload.clientId);
    console.log("Limit ", limit);
    if (!limit.remaining) {
      console.error("Rate limit exceeded. Please try again after sometime.");
      message = "Rate limit exceeded. Please try again after sometime.";
      status = "deny";
    }
  } catch (e) {
    console.log(e);
    message = "Invalid token or Access token expired";
    status = "unauthorized";
  }
  let methodArn = event.methodArn;
  switch (status) {
    case "allow":
      return generatePolicy(
        "user",
        "Allow",
        methodArn,
        authtoken,
        payload,
        message
      );
    case "deny":
      return generatePolicy(
        "user",
        "Deny",
        methodArn,
        authtoken,
        payload,
        message
      );
    case "unauthorized":
      throw new Error("Unauthorized");
    default:
      throw new Error("Invalid token");
  }
};

// Help function to generate an IAM policy
var generatePolicy = function (
  principalId,
  effect,
  resource,
  originalToken,
  payload,
  message
) {
  var authResponse = {};

  authResponse.principalId = principalId;
  if (effect && resource) {
    var policyDocument = {};
    policyDocument.Version = "2012-10-17";
    policyDocument.Statement = [];
    var statementOne = {};
    statementOne.Action = "execute-api:Invoke";
    statementOne.Effect = effect;
    statementOne.Resource = resource;
    policyDocument.Statement[0] = statementOne;
    authResponse.policyDocument = policyDocument;
  }

  authResponse.context = {
    message: message,
  };
  if (payload != null && payload.clientId != null) {
    authResponse.usageIdentifierKey = payload.clientId;
  }
  console.log("authResponse 1 : ", JSON.stringify(authResponse));

  return authResponse;
};
