
const admin = require('firebase-admin');
const firebaseDatabaseEndpoint = process.env.FIREBASE_DATABASE_ENDPOINT;

const serviceAccount = require('./admin.json');

serviceAccount.project_id = process.env.FIREBASE_SA_PROJECT_ID;
serviceAccount.private_key_id = process.env.FIREBASE_SA_PRIVATE_KEY_ID;
serviceAccount.private_key = process.env.FIREBASE_SA_PRIVATE_KEY;
serviceAccount.client_email = process.env.FIREBASE_SA_CLIENT_EMAIL;
serviceAccount.client_id = process.env.FIREBASE_SA_CLIENT_ID;
serviceAccount.client_x509_cert_url = process.env.FIREBASE_SA_CX509_CERT_URL;
console.log("serviceAccount: ", serviceAccount);

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
    databaseURL: firebaseDatabaseEndpoint,
})

exports.lambdaHandler = async (event, context, callback) => {

    console.info("START");
    console.log("event: ", event);
    console.log("event.authorizationToken: ", event.authorizationToken);

    // firebase uid 検証
    
    const uid = await admin.auth().verifyIdToken(event.authorizationToken)
        .then((decodedToken) => {
            console.log("decodedToken: ",decodedToken);
            return decodedToken.uid;
        })
        .catch((error) => {
            console.log(error);
            return null;
        })

    if (uid) {
        // 検証に成功している場合実行する処理
        console.log('hello firebase');

        const response = {
            'statusCode': 200,
            'body': JSON.stringify({
                message: 'verify token success.',
                uid: uid
            })
        };
        console.log("response: ", response);

        // return response;
        callback(null, generatePolicy('user', 'Allow', event.methodArn));
    }
    else {
        const response = {
            statusCode: 500,
            body: {
                message: 'verify token failure.'
            },
        };

        // return response;
        callback("Unauthorized");
    }
};

// Help function to generate an IAM policy
var generatePolicy = function(principalId, effect, resource) {
    var authResponse = {};
    
    authResponse.principalId = principalId;
    if (effect && resource) {
        var policyDocument = {};
        policyDocument.Version = '2012-10-17'; 
        policyDocument.Statement = [];
        var statementOne = {};
        statementOne.Action = 'execute-api:Invoke'; 
        statementOne.Effect = effect;
        statementOne.Resource = resource;
        policyDocument.Statement[0] = statementOne;
        authResponse.policyDocument = policyDocument;
    }
    
    // Optional output with custom properties of the String, Number or Boolean type.
    authResponse.context = {
        "stringKey": "stringval",
        "numberKey": 123,
        "booleanKey": true
    };
    return authResponse;
}