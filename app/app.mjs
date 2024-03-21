import { CognitoJwtVerifier } from "aws-jwt-verify";

const verifier = CognitoJwtVerifier.create({
    userPoolId: process.env.COGNITO_USER_POOL_ID,
    tokenUse: "id",
    clientId: process.env.COGNITO_CLIENT_ID,
});

const generatePolicy = function(principalId, effect, resource, email) {
    return {
        "principalId": principalId,
        "policyDocument": {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Action": "execute-api:Invoke",
                    "Effect": effect,
                    "Resource": resource
                }
            ]
        },
        "context": {
            "employeeId": principalId,
            "employeeEmail": email
        }
    };
};

export const handler = async (event) => {
    try {
        console.log(`Event: ${JSON.stringify(event)}`);

        const token = event.authorizationToken.split(' ')[1];
        const decodedToken = await verifier.verify(token);
        console.log(`Token is valid. Payload: ${JSON.stringify(decodedToken)}`);

        return generatePolicy(decodedToken["cognito:username"], "Allow", event.methodArn, decodedToken["email"]);
    } catch (error) {
        console.log(`Token not valid. Error: ${error}`);
        return generatePolicy("undefined", "Deny", event.methodArn, "undefined");
    }
}