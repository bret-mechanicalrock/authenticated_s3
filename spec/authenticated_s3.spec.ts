import * as request from "request-promise-native";
(global as any).fetch = require('node-fetch');
import Amplify from 'aws-amplify';


describe("Authenticated S3", () => {

    const cloudFrontDomain = "https://d3mp7ged87krmp.cloudfront.net"
    const securedObject = `${cloudFrontDomain}/private/top-secret.json`
    const nonExistantObject = `${cloudFrontDomain}/private/this-does-not-exist.json`
    const nonExistantObjectRoot = `${cloudFrontDomain}/this-does-not-exist.json`
    const cognitoDetails = {
        Auth: {
            // REQUIRED - Amazon Cognito Region
            region: 'us-east-1',

            // OPTIONAL - Amazon Cognito User Pool ID
            userPoolId: 'us-east-1_GFLHTFnPy',

            // OPTIONAL - Amazon Cognito Web Client ID (26-char alphanumeric string)
            userPoolWebClientId: '65j6nu2kk7du7por84gvu6qo9u',

            // OPTIONAL - Manually set the authentication flow type. Default is 'USER_SRP_AUTH'
            authenticationFlowType: 'USER_SRP_AUTH'
        }
    }

    describe("When authenticated against cognito", () => {
        let jwtToken;
        beforeAll(async (done) => {
            try {
                jwtToken = await logIntoCognito()
            } catch (err) {
                done.fail(err)
            }

            done()
        }, 30 * 1000)

        it('should grant access to a secured object', async (done) => {
            try {
                await request({
                    uri: securedObject,
                    json: true,
                    headers: {
                        Authorization: "Bearer " + jwtToken
                    }
                })
                done()
            } catch (err) {
                console.log(err)
                done.fail("request should have succeeded")
            }
        })

        it('should return forbidden (403) for non-existant object', async (done) => {
            try {
                await request({
                    uri: nonExistantObject,
                    json: true,
                    headers: {
                        Authorization: "Bearer " + jwtToken
                    }
                })
                done.fail("request should have returned '(403)'")
            } catch (err) {
                expect(err.statusCode).toEqual(403)
                done()
            }
        })
    })

    describe("When unauthenticated", () => {

        it('should return unauthorised (401) for a secured object', async (done) => {
            try {
                await request({
                    uri: securedObject,
                    json: true
                })
                done.fail("request should have failed")
            } catch (err) {
                expect(err.statusCode).toEqual(401)
                done()
            }
        })

        it('should return unauthorised (401) for non-existant protected object', async (done) => {
            try {
                await request({
                    uri: nonExistantObject,
                    json: true
                })
                done.fail("request should have failed")
            } catch (err) {
                expect(err.statusCode).toEqual(401)
                done()
            }
        })

        it('should return unauthorised (401) for non-existant protected object at any path', async (done) => {
            try {
                await request({
                    uri: nonExistantObjectRoot,
                    json: true
                })
                done.fail("request should have failed")
            } catch (err) {
                expect(err.statusCode).toEqual(401)
                done()
            }
        })
    })

    async function logIntoCognito(): Promise<string> {
        Amplify.configure(cognitoDetails);
        await Amplify.Auth.signIn('bret', 'Temporary_1');
        const session = await Amplify.Auth.currentSession()
        return session.accessToken.jwtToken
    }
})